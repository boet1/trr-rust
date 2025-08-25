import os
import json
import sys
import re
from tree_sitter import Language, Parser
import tree_sitter_rust as tsrust

# Initialize Rust language parser (preserving original style)
RUST_LANGUAGE = Language(tsrust.language())
parser = Parser(RUST_LANGUAGE)

# ------------------------------------------------------------
# Anchor helper CPIs (wrapped, without ::cpi::)
# ------------------------------------------------------------

# Common helper names used by Anchor-based CPI wrappers
ANCHOR_HELPER_NAMES = {
    # SPL Token
    "transfer", "transfer_checked",
    "mint_to", "mint_to_checked",
    "burn", "burn_checked",
    "approve", "revoke",
    "set_authority",
    "initialize_account3", "initialize_account2",
    "initialize_mint2",
    "sync_native",
    # Associated Token
    "create", "create_idempotent",
    # System program
    "transfer",
}

# Byte-strings to match in callee's full path to infer module/program hints
ANCHOR_HELPER_MODULE_HINTS = {
    b"anchor_spl::token",
    b"anchor_spl::associated_token",
    b"anchor_lang::system_program",
    # Also accept common aliases after `use ... as ...`
    b"token",
    b"associated_token",
    b"system_program",
}


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def read_rust_code(file_path):
    """Reads Rust code and returns (str, bytes)."""
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return code, code.encode('utf8')

def collect_ast_lines(node, indent=""):
    """Collects all AST nodes as indented text lines."""
    lines = [f"{indent}{node.type} ({node.start_point} - {node.end_point})"]
    for child in node.children:
        lines.extend(collect_ast_lines(child, indent + "  "))
    return lines

def node_text(code_bytes, node):
    """Returns source text of a node as UTF-8 string."""
    return code_bytes[node.start_byte:node.end_byte].decode('utf8', errors='ignore')

def get_line_and_col(node):
    """1-based line/column from node.start_point."""
    r, c = node.start_point
    return r + 1, c + 1

def get_line_str(code_str, line_no):
    """Returns the raw line text (1-based)."""
    lines = code_str.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].rstrip()
    return ""

def is_ident_invoke(name_bytes):
    return name_bytes == b'invoke'

def is_ident_invoke_signed(name_bytes):
    return name_bytes == b'invoke_signed'

def scoped_contains_cpi(scoped_bytes):
    return b'::cpi::' in scoped_bytes

def last_segment(bytes_path):
    parts = bytes_path.split(b'::')
    return parts[-1] if parts else bytes_path

def find_child_of_type(node, kind):
    for ch in node.children:
        if ch.type == kind:
            return ch
    return None

def find_all_children_of_type(node, kind):
    out = []
    for ch in node.children:
        if ch.type == kind:
            out.append(ch)
    return out


def _find_arguments_node(call_node):
    for ch in call_node.children:
        if ch.type == "arguments":
            return ch
    return None

def _has_cpi_context_hint(call_node, code_bytes):
    """
    Scan the call's arguments subtree for 'CpiContext' or 'with_signer' hints.
    """
    args = _find_arguments_node(call_node)
    if args is None:
        return False
    stack = [args]
    while stack:
        cur = stack.pop()
        if cur.type in ("type_identifier", "identifier", "scoped_identifier", "field_expression"):
            txt = node_text(code_bytes, cur)
            if "CpiContext" in txt or "with_signer" in txt:
                return True
        stack.extend(cur.children)
    return False

def _nearest_enclosing_scope(node):
    """
    Climb parents to find a reasonable enclosing scope (function/block/impl).
    """
    cur = node
    # Using .parent is supported by tree-sitter Python nodes
    while cur is not None:
        if cur.type in ("function_item", "block", "impl_item"):
            return cur
        cur = getattr(cur, "parent", None)
    return None

def _scope_has_cpi_context_before_call(call_node, code_bytes):
    """
    Fallback heuristic: within the enclosing scope (function/block), check if
    textual 'CpiContext' or 'with_signer' appears before the call site.
    This catches patterns like:
        let ctx = CpiContext::new(...);
        transfer(ctx, ...);
    where the call arguments don't literally contain 'CpiContext'.
    """
    scope = _nearest_enclosing_scope(call_node)
    if scope is None:
        return False
    start = scope.start_byte
    end = call_node.start_byte
    if start >= end:
        return False
    window = code_bytes[start:end]
    return (b"CpiContext" in window) or (b"with_signer" in window)

_ALIAS_RE = None
def _resolve_alias_helper_identifier(alias_name, call_node, code_bytes):
    """
    Try to resolve identifiers like `sys_transfer` or `spl_transfer` to known helpers by scanning
    earlier `use` declarations of the form:
      use <path>::<helper> as <alias>;
    Returns the canonical helper name if it maps to a known helper, else None.
    """
    global _ALIAS_RE
    if _ALIAS_RE is None:
        # Forgiving regex; we only scan the bytes before the call site
        _ALIAS_RE = re.compile(
            rb"use\s+([A-Za-z0-9_:\s]+?)::([A-Za-z0-9_]+)\s+as\s+([A-Za-z0-9_]+)\s*;"
        )
    # Limit search to content before the call (within the whole file)
    prefix = code_bytes[:call_node.start_byte]
    for m in _ALIAS_RE.finditer(prefix):
        full_path = m.group(1).replace(b" ", b"")
        helper = m.group(2).decode("utf-8", errors="ignore")
        alias  = m.group(3).decode("utf-8", errors="ignore")
        if alias == alias_name and helper in ANCHOR_HELPER_NAMES:
            # Require path hints to reduce false positives
            if any(h in full_path for h in ANCHOR_HELPER_MODULE_HINTS):
                return helper  # canonical helper name
    return None

# ------------------------------------------------------------
# Support: detect CpiContext params in function signature & first-arg usage
# + closures (confirmed and high confidence)
# ------------------------------------------------------------

def _function_item_of(node):
    """Ascend to the enclosing function_item (if any)."""
    cur = node
    while cur is not None and cur.type != "function_item":
        cur = getattr(cur, "parent", None)
    return cur

_PARAM_NAME_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*:")
def _cpi_context_param_names(func_item, code_bytes):
    """
    Returns a set of parameter identifiers declared as CpiContext<...> in the
    function signature like: fn f(ctx: CpiContext<Transfer>, ...).
    """
    if func_item is None:
        return set()
    # Find the 'parameters' child if present
    params_node = find_child_of_type(func_item, "parameters")
    if params_node is None:
        # older grammars may expose parameter children directly
        params_node = func_item
    names = set()
    for ch in params_node.children:
        if ch.type == "parameter":
            txt = node_text(code_bytes, ch)
            if "CpiContext" in txt:
                m = _PARAM_NAME_RE.match(txt)
                if m:
                    names.add(m.group(1))
    return names

def _first_arg_identifier_name(call_node, code_bytes):
    """
    Try to extract the *identifier* name of the first argument.
    Be robust: skip punctuation and, if needed, descend into wrappers like
    parenthesized_expression / unary_expression to find the leftmost identifier.
    """
    args = _find_arguments_node(call_node)
    if args is None or not args.children:
        return None

    def base_identifier_of(n):
        # Peel through references, parentheses, fields, method calls, etc.
        t = n.type
        if t == "identifier":
            return node_text(code_bytes, n)
        # Reference or parenthesized or unary
        if t in ("parenthesized_expression", "unary_expression", "reference_expression"):
            for ch in n.children:
                res = base_identifier_of(ch)
                if res:
                    return res
            return None
        # field_access like ctx.accounts
        if t == "field_expression":
            receiver = n.child_by_field_name("argument") or (n.children[0] if n.children else None)
            return base_identifier_of(receiver) if receiver else None
        # call expression like ctx(...)
        if t == "call_expression":
            callee = n.child_by_field_name("function")
            return base_identifier_of(callee) if callee else None
        # scoped identifier or qualified type: take left-most
        if t in ("scoped_identifier", "qualified_type", "generic_type"):
            child = n.children[0] if n.children else None
            return base_identifier_of(child) if child else None
        # Fallback: try first child
        if n.children:
            return base_identifier_of(n.children[0])
        return None

    # iterate children; skip punctuation tokens like '(', ')', ',' if present
    for ch in args.children:
        if ch.type in (",", "(", ")"):
            continue
        # First non-punctuation child is the first argument expression
        ident = base_identifier_of(ch)
        return ident  # may be None if complex (ok)
    return None

# ---------- Closures ----------

def _enclosing_closure(node):
    """Ascend to the nearest closure_expression (if any)."""
    cur = node
    while cur is not None and cur.type != "closure_expression":
        cur = getattr(cur, "parent", None)
    return cur

def _closure_param_segment(closure_node, code_bytes):
    """
    Return the raw text between the first pair of '|' ... '|' of a closure.
    Heuristic that works for typical closures.
    """
    if closure_node is None:
        return ""
    text = node_text(code_bytes, closure_node)
    try:
        start = text.index('|') + 1
        end = text.index('|', start)
        return text[start:end]
    except ValueError:
        return ""

def _closure_params_with_cpicontext(closure_node, code_bytes):
    """
    Return a set of closure parameter names that are explicitly typed as CpiContext<...>.
    """
    seg = _closure_param_segment(closure_node, code_bytes)
    if not seg:
        return set()
    out = set()
    for part in seg.split(','):
        part = part.strip()
        if not part:
            continue
        if "CpiContext" in part:
            m = re.match(r"^([A-Za-z_]\w*)\s*:", part)
            if m:
                out.add(m.group(1))
    return out

def _outer_scope_has_cpi_before_closure(call_node, code_bytes):
    """
    Improved heuristic for closures:
    Look from the nearest enclosing function/block (not just the direct parent)
    up to the start of the closure for CpiContext/with_signer evidence.
    """
    closure = _enclosing_closure(call_node)
    if closure is None:
        return False
    # climb to a reasonable outer scope
    outer = _nearest_enclosing_scope(closure)
    if outer is None:
        return False
    start = outer.start_byte
    end = closure.start_byte
    if start >= end:
        return False
    window = code_bytes[start:end]
    return (b"CpiContext" in window) or (b"with_signer" in window)

# ------------------------------------------------------------
# Lightweight symbol table for CpiContext-like variables
# ------------------------------------------------------------

class ScopeInfo:
    def __init__(self, parent=None):
        self.parent = parent
        self.cpi_ctx_vars = set()   # variable names known/suspected to be CpiContext-like

    def resolve_is_cpi_ctx(self, name: str) -> bool:
        s = self
        while s:
            if name in s.cpi_ctx_vars:
                return True
            s = s.parent
        return False

def _is_expr_cpi_ctx_like(expr_text: str) -> bool:
    # textual hints that this expression constructs or derives a CpiContext
    return ("CpiContext::new" in expr_text) or ("with_signer" in expr_text)

def _collect_let_identifier_and_init(node, code_bytes):
    """
    Extract `let <ident> = <expr>;` returning (ident_name, init_node, init_text)
    """
    name = None
    init_node = node.child_by_field_name("value")
    # pattern
    pat = node.child_by_field_name("pattern")
    if pat and pat.type == "identifier":
        name = node_text(code_bytes, pat)
    else:
        # fallback: first identifier child
        for ch in node.children:
            if ch.type == "identifier":
                name = node_text(code_bytes, ch)
                break
    init_text = node_text(code_bytes, init_node) if init_node else ""
    return name, init_node, init_text

def _base_identifier_of_expr(n, code_bytes):
    """Find base identifier of an expression (e.g., ctx in &mut ctx.accounts or ctx.with_signer(...))."""
    if n is None:
        return None
    t = n.type
    if t == "identifier":
        return node_text(code_bytes, n)
    if t in ("parenthesized_expression", "unary_expression", "reference_expression"):
        for ch in n.children:
            res = _base_identifier_of_expr(ch, code_bytes)
            if res:
                return res
        return None
    if t == "field_expression":
        receiver = n.child_by_field_name("argument") or (n.children[0] if n.children else None)
        return _base_identifier_of_expr(receiver, code_bytes)
    if t == "call_expression":
        callee = n.child_by_field_name("function")
        return _base_identifier_of_expr(callee, code_bytes)
    if t in ("scoped_identifier", "qualified_type", "generic_type"):
        child = n.children[0] if n.children else None
        return _base_identifier_of_expr(child, code_bytes)
    if n.children:
        return _base_identifier_of_expr(n.children[0], code_bytes)
    return None

# ------------------------------------------------------------
# CPI detection
# ------------------------------------------------------------

def classify_call_expr(call_node, code_bytes, scope_info: ScopeInfo):
    """
    Given a call_expression node, classify it as one of:
      - invoke
      - invoke_signed
      - anchor_cpi_helper
      - anchor_cpi_helper_wrapped
      - method_invoke
      - method_invoke_signed
    Or return None if not a CPI site.
    """
    # find function subexpression (identifier/scoped_identifier/field_expression)
    func = None
    for ch in call_node.children:
        if ch.type in ('identifier', 'scoped_identifier', 'field_expression'):
            func = ch
            break
    if func is None:
        return None

    # Helper: determine if first arg name is a CpiContext param from signature
    func_item = _function_item_of(call_node)
    cpi_param_names = _cpi_context_param_names(func_item, code_bytes)
    first_arg_name = _first_arg_identifier_name(call_node, code_bytes)

    # Evidence from closures
    closure = _enclosing_closure(call_node)
    closure_cpi_params = _closure_params_with_cpicontext(closure, code_bytes)
    first_arg_is_closure_param_with_type = bool(first_arg_name and first_arg_name in closure_cpi_params)
    first_arg_is_param_from_func = bool(first_arg_name and first_arg_name in cpi_param_names)

    def _has_confirmed_or_high_confidence(full_path_bytes=None):
        # Confirmed evidence
        if _has_cpi_context_hint(call_node, code_bytes):
            return True
        if first_arg_is_closure_param_with_type:
            return True
        if first_arg_is_param_from_func:
            return True
        if _scope_has_cpi_context_before_call(call_node, code_bytes):
            return True

        # New: if first arg resolves to a CpiContext-like variable in outer scopes (captured in closure)
        if first_arg_name and scope_info and scope_info.resolve_is_cpi_ctx(first_arg_name):
            return True

        # High confidence: first arg is a closure parameter (untyped) and outer function/block shows hints
        if first_arg_name and closure is not None:
            params_seg = _closure_param_segment(closure, code_bytes)
            if params_seg:
                params = [p.strip().split(':')[0].strip() for p in params_seg.split(',') if p.strip()]
                if first_arg_name in params and _outer_scope_has_cpi_before_closure(call_node, code_bytes):
                    return True

        # For scoped identifiers: allow module hints + typed param evidence
        if full_path_bytes is not None and first_arg_is_param_from_func:
            if any(h in full_path_bytes for h in ANCHOR_HELPER_MODULE_HINTS):
                return True
        return False

    if func.type == 'identifier':
        name = node_text(code_bytes, func).encode('utf8')
        if is_ident_invoke(name):
            return 'invoke', func
        if is_ident_invoke_signed(name):
            return 'invoke_signed', func
        # Wrapped helper via identifier (likely alias): require confirmed/high-confidence evidence
        last = name.decode('utf8', errors='ignore')
        canon = last if last in ANCHOR_HELPER_NAMES else _resolve_alias_helper_identifier(last, call_node, code_bytes)
        if canon and _has_confirmed_or_high_confidence():
            return 'anchor_cpi_helper_wrapped', func
        return None

    if func.type == 'scoped_identifier':
        full = node_text(code_bytes, func).encode('utf8')
        if scoped_contains_cpi(full):
            return 'anchor_cpi_helper', func
        # handle module::invoke(...) and module::invoke_signed(...)
        tail = last_segment(full)
        if is_ident_invoke(tail):
            return 'invoke', func
        if is_ident_invoke_signed(tail):
            return 'invoke_signed', func
        # Wrapped helper via module path: allow confirmed/high-confidence evidence
        last = tail.decode('utf8', errors='ignore')
        if last in ANCHOR_HELPER_NAMES:
            if _has_confirmed_or_high_confidence(full_path_bytes=full):
                return 'anchor_cpi_helper_wrapped', func
        return None

    if func.type == 'field_expression':
        # method call: obj.<field_identifier>(...)
        field_id = find_child_of_type(func, 'field_identifier')
        if field_id is None:
            return None
        name = node_text(code_bytes, field_id).encode('utf8')
        if is_ident_invoke(name):
            return 'method_invoke', field_id
        if is_ident_invoke_signed(name):
            return 'method_invoke_signed', field_id
        # Conservatively detect helpers as methods only if we have confirmed/high-confidence evidence
        last = name.decode('utf8', errors='ignore')
        canon = last if last in ANCHOR_HELPER_NAMES else _resolve_alias_helper_identifier(last, call_node, code_bytes)
        if canon and _has_confirmed_or_high_confidence():
            return 'anchor_cpi_helper_wrapped', field_id
        return None

    return None

def walk_calls_and_collect(node, code_str, code_bytes, hits, scope_info: ScopeInfo):
    """Recursively traverse the AST and collect CPI hits with scope tracking."""
    # Enter new scope on blocks and function items
    opened_scope_here = False
    if node.type in ("block", "function_item", "impl_item", "closure_expression"):
        scope_info = ScopeInfo(parent=scope_info)
        opened_scope_here = True

    # Track CpiContext-like lets within this scope
    if node.type in ("let_declaration", "let_declaration_statement", "let_declaration"):
        name, init_node, init_text = _collect_let_identifier_and_init(node, code_bytes)
        if name:
            # Direct construction / chaining
            if _is_expr_cpi_ctx_like(init_text):
                scope_info.cpi_ctx_vars.add(name)
            else:
                # e.g., let x = ctx.with_signer(...);
                base = _base_identifier_of_expr(init_node, code_bytes)
                if base and scope_info.resolve_is_cpi_ctx(base):
                    scope_info.cpi_ctx_vars.add(name)

    if node.type == 'call_expression':
        res = classify_call_expr(node, code_bytes, scope_info)
        if res is not None:
            kind, marker_node = res
            line, col = get_line_and_col(marker_node)
            callee_text = node_text(code_bytes, marker_node)
            code_line = get_line_str(code_str, line)
            hits.append({
                'line': line,
                'col': col,
                'kind': kind,
                'callee': callee_text,
                'code': code_line
            })

    # Recurse
    for ch in node.children:
        walk_calls_and_collect(ch, code_str, code_bytes, hits, scope_info)

# ------------------------------------------------------------
# File processing
# ------------------------------------------------------------

def process_file(file_path, output_dir):
    """Parses a Rust file, writes AST, and returns CPI hits and totals."""
    print(f"🔎 Processing file: {file_path}")
    code_str, code_bytes = read_rust_code(file_path)
    tree = parser.parse(code_bytes)
    root = tree.root_node

    # Write AST to .txt file
    ast_lines = collect_ast_lines(root)
    ast_file_name = os.path.basename(file_path).replace('.rs', '_ast.txt')
    ast_output_path = os.path.join(output_dir, ast_file_name)
    with open(ast_output_path, 'w', encoding='utf-8') as ast_file:
        ast_file.write('\n'.join(ast_lines))
    print(f"✅ AST written to {ast_output_path}")

    # Collect CPI hits
    hits = []
    walk_calls_and_collect(root, code_str, code_bytes, hits, ScopeInfo(parent=None))

    # Sort hits by position
    hits.sort(key=lambda h: (h['line'], h['col']))

    # Totals for this file
    counts = {}
    for h in hits:
        k = h['kind']
        counts[k] = counts.get(k, 0) + 1

    total_cpi = (
        counts.get('invoke', 0)
        + counts.get('invoke_signed', 0)
        + counts.get('method_invoke', 0)
        + counts.get('method_invoke_signed', 0)
        + counts.get('anchor_cpi_helper', 0)
        + counts.get('anchor_cpi_helper_wrapped', 0)
    )

    return {
        'ast_file': ast_file_name,
        'hits': hits,
        'totals': {
            **counts,
            'total_cpi': total_cpi
        }
    }

def find_rust_files(paths):
    """Finds all .rs files in provided paths (files or directories)."""
    rust_files = []
    for path in paths:
        if os.path.isfile(path) and path.endswith('.rs'):
            rust_files.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith('.rs'):
                        rust_files.append(os.path.join(root, file))
    return rust_files

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("❗ Please provide at least one file or folder path to analyze.")
        sys.exit(1)

    input_paths = sys.argv[1:]
    rust_files = find_rust_files(input_paths)

    if not rust_files:
        print("❗ No .rs files found to process.")
        sys.exit(1)

    output_dir = "output_results"
    os.makedirs(output_dir, exist_ok=True)

    summary = {}
    grand_totals = {}

    # Process each Rust file
    for file_path in rust_files:
        result = process_file(file_path, output_dir)
        summary[file_path] = result
        # accumulate global totals
        for k, v in result['totals'].items():
            grand_totals[k] = grand_totals.get(k, 0) + v

    # Write the summary JSON with all CPI data
    summary_path = os.path.join(output_dir, 'cpi_summary.json')
    with open(summary_path, 'w', encoding='utf-8') as json_file:
        json.dump({
            'files': summary,
            'global_totals': grand_totals
        }, json_file, indent=2, ensure_ascii=False)

    print(f"\n✅ CPI summary written to {summary_path}")

if __name__ == "__main__":
    main()
