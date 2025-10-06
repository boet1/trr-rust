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
# ---- CPI low-level entrypoints (Solana runtime + common wrappers) ----
# Match function or method names like:
#  - invoke, invoke_signed, invoke_unchecked, invoke_signed_unchecked
#  - program_invoke, program_invoke_signed, program_invoke_unchecked, ...
#  - invoke_with_program_id, program_invoke_with_program_id, ...
CPI_ENTRYPOINT_NAME_PATTERNS = [
    re.compile(r"^invoke(?:_signed)?(?:_unchecked)?$", re.ASCII),
    re.compile(r"^invoke(?:_signed)?_with_program_id$", re.ASCII),
]

# Optional module hints for extra confidence when available
CPI_ENTRYPOINT_MODULE_HINTS = {
    b"solana_program::program",
    b"anchor_lang::solana_program::program",
    b"solana_program",
}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _qualify_bare_ident_local(name: str, caller_q: str, file_module_path: str, local_mods: set, local_qnames: set) -> str:

    candidates = []
    if caller_q:
        prefix = caller_q.rsplit("::", 1)[0]
        candidates.append(f"{prefix}::{name}")
    if file_module_path:
        candidates.append(f"{file_module_path}::{name}")
        for lm in local_mods:
            candidates.append(f"{file_module_path}::{lm}::{name}")
    for q in candidates:
        if q in local_qnames:
            return q
    return name


def _qualify_bare_ident_repo(name: str, caller_q: str, file_module_path: str, local_mods: set, repo_func_meta: dict) -> str:
    candidates = []
    if caller_q:
        prefix = caller_q.rsplit("::", 1)[0]
        candidates.append(f"{prefix}::{name}")
    if file_module_path:
        candidates.append(f"{file_module_path}::{name}")
        for lm in local_mods:
            candidates.append(f"{file_module_path}::{lm}::{name}")

    for q in candidates:
        if q in repo_func_meta:
            return q

    matches = [q for q, m in repo_func_meta.items() if m.get('name') == name]
    if len(matches) == 1:
        return matches[0]

    return name


def file_module_path_from(file_path: str) -> str:
    """
    Derive a stable, short module prefix from the file path:
      - lib.rs / main.rs    -> ""
      - foo.rs              -> "foo"
      - foo/mod.rs          -> "foo"
      - foo/bar.rs          -> "bar"   (prefer short, file-based)
      - foo/bar/mod.rs      -> "bar"
    Rationale: matches how many repos refer to items due to re-exports.
    """
    p = os.path.normpath(file_path)
    base = os.path.basename(p)  # e.g., "bar.rs" or "mod.rs"
    name, _ = os.path.splitext(base)
    if name in ("lib", "main"):
        return ""
    if name == "mod":
        parent = os.path.basename(os.path.dirname(p))
        return "" if parent in ("src", "") else parent
    return name
    
def file_pass2_tag_wrappers(file_path, wrapper_fn_qnames_global, wrapper_method_names_global,func_meta_by_qname_global):
    """
    Second pass per file: tag callsites that target repo-wide wrappers as 'wrapper_cpi'.
    Returns list of wrapper hits for this file.
    """
    code_str, code_bytes = read_rust_code(file_path)
    tree = parser.parse(code_bytes)
    root = tree.root_node

    file_module_path = file_module_path_from(file_path)
    local_mods = collect_local_mod_names(root, code_bytes)

    # Collect local function qnames (not strictly required here, but useful for debugging)
    local_func_qnames = set()
    def _scan_local_qnames(node):
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "function_item":
                q = qualified_name_of_function(n, code_bytes, file_module_path)
                local_func_qnames.add(q)
            stack.extend(n.children)
    _scan_local_qnames(root)

    wrapper_hits = []

    def _walk(n, current_func_q=None):
        # Track the current function qualified name
        if n.type == "function_item":
            current_func_q = qualified_name_of_function(n, code_bytes, file_module_path)

        if n.type == 'call_expression':
            name, full_path, marker = extract_callee_name_and_path(n, code_bytes)
            if name and marker:
                is_method = (marker.type == 'field_identifier')

                # ---- Method call case: obj.method(...)
                if is_method:
                    if name in wrapper_method_names_global:
                        line, col = get_line_and_col(marker)
                        callee_text = node_text(code_bytes, marker)
                        code_line = get_line_str(code_str, line)
                        wrapper_hits.append({
                            'line': line, 'col': col,
                            'kind': 'wrapper_cpi',
                            'callee': callee_text,
                            'reason': f'via_wrapper_method:{name}',
                            'code': code_line
                        })

                # ---- Function/scoped call case: fn(...), module::fn(...)
                else:
                    if full_path is not None:
                        # We have a module path; normalize relative module paths inside the same file
                        callee_key = full_path.decode('utf8', errors='ignore')
                        if "::" in callee_key and file_module_path:
                            first_seg = callee_key.split("::", 1)[0]
                            if first_seg in local_mods and not callee_key.startswith(file_module_path + "::"):
                                callee_key = f"{file_module_path}::{callee_key}"
                    else:
                        # Bare identifier: qualify using repo-wide metadata so it can match wrapper qnames
                        callee_key = _qualify_bare_ident_repo(
                            name=name,
                            caller_q=current_func_q,
                            file_module_path=file_module_path,
                            local_mods=local_mods,
                            repo_func_meta=func_meta_by_qname_global
                        )

                    if callee_key in wrapper_fn_qnames_global:
                        line, col = get_line_and_col(marker)
                        callee_text = node_text(code_bytes, marker)
                        code_line = get_line_str(code_str, line)
                        wrapper_hits.append({
                            'line': line, 'col': col,
                            'kind': 'wrapper_cpi',
                            'callee': callee_text,
                            'reason': f'via_wrapper_fn:{callee_key}',
                            'code': code_line
                        })

        for ch in n.children:
            _walk(ch, current_func_q)

    _walk(root, None)
    return wrapper_hits


def propagate_wrappers_repo_wide(wrapper_fn_qnames, wrapper_method_names, edges_fn, edges_meth, func_meta_by_qname):
    """
    Propagate wrapper status across the repository call graph until fixpoint.
    - If a caller calls a callee that is a wrapper (by fn qname match OR method name match),
      then the caller is also a wrapper.
    """
    # Build adjacency
    callers_to_fn_callees = {}
    callers_to_method_callees = {}
    for caller, callee in edges_fn:
        callers_to_fn_callees.setdefault(caller, set()).add(callee)
    for caller, meth in edges_meth:
        callers_to_method_callees.setdefault(caller, set()).add(meth)

    changed = True
    while changed:
        changed = False
        for caller_q in set(list(callers_to_fn_callees.keys()) + list(callers_to_method_callees.keys())):
            # methods
            for meth in callers_to_method_callees.get(caller_q, ()):
                if meth in wrapper_method_names:
                    meta = func_meta_by_qname.get(caller_q, {'is_method': False, 'name': None})
                    if meta.get('is_method'):
                        if meta['name'] not in wrapper_method_names:
                            wrapper_method_names.add(meta['name']); changed = True
                    else:
                        if caller_q not in wrapper_fn_qnames:
                            wrapper_fn_qnames.add(caller_q); changed = True

            # functions (EXACT match only)
            for callee_path in callers_to_fn_callees.get(caller_q, ()):
                if callee_path in wrapper_fn_qnames:
                    meta = func_meta_by_qname.get(caller_q, {'is_method': False, 'name': None})
                    if meta.get('is_method'):
                        if meta['name'] not in wrapper_method_names:
                            wrapper_method_names.add(meta['name']); changed = True
                    else:
                        if caller_q not in wrapper_fn_qnames:
                            wrapper_fn_qnames.add(caller_q); changed = True

    return wrapper_fn_qnames, wrapper_method_names


def file_pass1_scan(file_path, output_dir):
    """
    Pass 1 (per file):
      - parse + write AST
      - collect direct_cpi hits
      - collect wrappers_local (fn qnames, method names)
      - collect edges (caller->callee) for repo-wide propagation
      - collect legacy hits (optional) only if not direct_cpi at that callsite
    Returns a dict with per-file data.
    """
    print(f"🔎 Processing file (pass1): {file_path}")
    code_str, code_bytes = read_rust_code(file_path)
    tree = parser.parse(code_bytes)
    root = tree.root_node
    # Derive module path from file path for qname fallback
    file_module_path = file_module_path_from(file_path)
    local_mods = collect_local_mod_names(root, code_bytes)
    # AST out
    ast_lines = collect_ast_lines(root)
    ast_file_name = os.path.basename(file_path).replace('.rs', '_ast.txt')
    ast_output_path = os.path.join(output_dir, ast_file_name)
    with open(ast_output_path, 'w', encoding='utf-8') as ast_file:
        ast_file.write('\n'.join(ast_lines))
    print(f"✅ AST written to {ast_output_path}")

    # collect functions, calls and edges
    func_nodes, func_meta, calls_by_func, edges_fn, edges_meth = collect_functions_calls_and_edges(
        root, code_str, code_bytes, file_module_path,local_mods  
    )

    hits = []

    wrapper_fn_qnames_local = set()
    wrapper_method_names_local = set()

    # walk all calls again to classify
    def _walk_for_calls(n, current_func_q=None):
        if n.type == "function_item":
            current_func_q = qualified_name_of_function(n, code_bytes, file_module_path)

        if n.type == 'call_expression':
            # Pass 1: direct CPI (invoke*)
            direct = classify_call_expr_direct_cpi(n, code_bytes)
            if direct is not None:
                kind, marker_node, reason = direct
                line, col = get_line_and_col(marker_node)
                callee_text = node_text(code_bytes, marker_node)
                code_line = get_line_str(code_str, line)
                hits.append({
                    'line': line, 'col': col,
                    'kind': kind,  # 'direct_cpi'
                    'callee': callee_text,
                    'reason': reason,
                    'code': code_line
                })
                
                # mark the enclosing function as wrapper-local
                if current_func_q and current_func_q in func_nodes:
                    if func_meta[current_func_q]['is_method']:
                        wrapper_method_names_local.add(func_meta[current_func_q]['name'])
                    else:
                        wrapper_fn_qnames_local.add(current_func_q)
            else:
                # Optional legacy classification ONLY if no direct
                # (keeps your Anchor helpers / heuristics)
                
                res = classify_call_expr(n, code_bytes, ScopeInfo(parent=None))
                if res is not None:
                    legacy_kind, marker_node = res
                    line, col = get_line_and_col(marker_node)
                    callee_text = node_text(code_bytes, marker_node)
                    code_line = get_line_str(code_str, line)
                    hits.append({
                        'line': line, 'col': col,
                        'kind': legacy_kind,
                        'callee': callee_text,
                        'code': code_line
                    })

                    if current_func_q and current_func_q in func_nodes:
                        if legacy_kind in ('anchor_cpi_helper', 'anchor_cpi_helper_wrapped'):
                            if func_meta[current_func_q]['is_method']:
                                wrapper_method_names_local.add(func_meta[current_func_q]['name'])
                            else:
                                wrapper_fn_qnames_local.add(current_func_q)

        for ch in n.children:
            _walk_for_calls(ch, current_func_q)

    _walk_for_calls(root, None)

    return {
        'ast_file': ast_file_name,
        'hits_direct_and_legacy': hits,
        'wrapper_fn_qnames_local': wrapper_fn_qnames_local,
        'wrapper_method_names_local': wrapper_method_names_local,
        'edges_fn': edges_fn,
        'edges_meth': edges_meth,
        'func_meta': func_meta,
    }

def collect_functions_calls_and_edges(root, code_str, code_bytes, file_module_path: str, local_mods: set):
    """
    Returns:
      func_nodes: dict[qname] = function_item node
      func_meta:  dict[qname] = {'is_method': bool, 'name': str}  # name is method/fn short name
      calls_by_func: dict[qname] = list[call_expression nodes]
      edges_fn: list[(caller_q, callee_path_str)]     # for identifier/scoped calls
      edges_meth: list[(caller_q, method_name_str)]   # for method calls (field_expression)
    """
    func_nodes, calls_by_func = {}, {}
    func_meta = {}
    edges_fn, edges_meth = [], []
    local_func_qnames = set()

    def _walk(n, current_func_q=None):
        nonlocal func_nodes, calls_by_func, func_meta, edges_fn, edges_meth
        if n.type == "function_item":
            q = qualified_name_of_function(n, code_bytes, file_module_path)
            func_nodes[q] = n
            calls_by_func[q] = []
            func_meta[q] = {
                'is_method': is_method_function(n),
                'name': function_name_of(n, code_bytes),
            }
            local_func_qnames.add(q)
            current_func_q = q

        if n.type == "call_expression" and current_func_q is not None:
            calls_by_func[current_func_q].append(n)
            # record edges (best-effort)
            name, full_path, marker = extract_callee_name_and_path(n, code_bytes)
            if name:
                if marker and marker.type == 'field_identifier':
                    # method call: obj.name(...)
                    edges_meth.append((current_func_q, name))
                else:
                    if full_path is not None:
                        callee_key = full_path.decode('utf8', errors='ignore')
                        if "::" in callee_key and file_module_path:
                            first_seg = callee_key.split("::", 1)[0]
                            if first_seg in local_mods and not callee_key.startswith(file_module_path + "::"):
                                callee_key = f"{file_module_path}::{callee_key}"

                    else:
                        callee_key = _qualify_bare_ident_local(
                            name=name,
                            caller_q=current_func_q,
                            file_module_path=file_module_path,
                            local_mods=local_mods,
                            local_qnames=local_func_qnames
                        )

                    edges_fn.append((current_func_q, callee_key))

        for ch in n.children:
            _walk(ch, current_func_q)

    _walk(root, None)
    return func_nodes, func_meta, calls_by_func, edges_fn, edges_meth


def is_method_function(func_item_node) -> bool:
    """Returns True if this function_item is inside an impl_item (i.e., a method), else False."""
    parent = getattr(func_item_node, "parent", None)
    while parent is not None:
        if parent.type == "impl_item":
            return True
        parent = getattr(parent, "parent", None)
    return False

def function_name_of(func_item_node, code_bytes) -> str:
    """Returns the function/method identifier name (unqualified)."""
    ident = find_child_of_type(func_item_node, "identifier")
    return node_text(code_bytes, ident) if ident else "<anon>"

def extract_callee_name_and_path(call_node, code_bytes):
    """
    Returns (name_str, full_path_bytes, node_for_location) where:
      - name_str: the rightmost identifier (e.g., 'invoke', 'program_invoke_signed')
      - full_path_bytes: b'module::...::name' if available (or None)
      - node_for_location: the node to use for line/col (identifier/field_identifier/scoped_identifier)
    """
    func = None
    for ch in call_node.children:
        if ch.type in ('identifier', 'scoped_identifier', 'field_expression'):
            func = ch
            break
    if func is None:
        return None, None, None

    if func.type == 'identifier':
        name = node_text(code_bytes, func)
        return name, None, func

    if func.type == 'scoped_identifier':
        full = node_text(code_bytes, func).encode('utf8', errors='ignore')
        tail = full.split(b'::')[-1] if full else b''
        return tail.decode('utf8', errors='ignore'), full, func

    if func.type == 'field_expression':
        field_id = find_child_of_type(func, 'field_identifier')
        if field_id is None:
            return None, None, None
        name = node_text(code_bytes, field_id)
        return name, None, field_id

    return None, None, None

def is_cpi_entrypoint_name(name: str) -> bool:
    if not name:
        return False
    for rx in CPI_ENTRYPOINT_NAME_PATTERNS:
        if rx.match(name):
            return True
    return False

def classify_call_expr_direct_cpi(call_node, code_bytes):
    """
    Return ('direct_cpi', marker_node, reason) if this call is a direct CPI boundary.
    Else None.
    """
    name, full_path, marker = extract_callee_name_and_path(call_node, code_bytes)
    if not name:
        return None
    if is_cpi_entrypoint_name(name):
        if full_path and any(h in full_path for h in CPI_ENTRYPOINT_MODULE_HINTS):
            return ('direct_cpi', marker, 'entrypoint+module_hint')
        return ('direct_cpi', marker, 'entrypoint_name')
    return None

def qualified_name_of_function(func_item_node, code_bytes, file_module_path: str = "") -> str:
    """
    Build a canonical qualified name:
      file_module_path  +  nested mod_items  +  function name

    Why:
      - The same symbol gets the same qname across files.
      - Matches common call-site style (e.g., token_ops::tokens::foo).
    """
    ident = find_child_of_type(func_item_node, "identifier")
    fname = node_text(code_bytes, ident) if ident else "<anon>"

    # Collect nested `mod` names inside the same file
    mod_parts = []
    cur = getattr(func_item_node, "parent", None)
    while cur is not None:
        if cur.type == "mod_item":
            mid = find_child_of_type(cur, "identifier")
            if mid:
                mod_parts.append(node_text(code_bytes, mid))
        cur = getattr(cur, "parent", None)
    mod_parts.reverse()  # outer-most first

    prefix = [file_module_path] if file_module_path else []
    parts = [p for p in prefix + mod_parts + [fname] if p]
    return "::".join(parts)

def read_rust_code(file_path):
    """Reads Rust code and returns (str, bytes)."""
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return code, code.encode('utf8')

def collect_local_mod_names(root, code_bytes):
    """
    Return the set of `mod` identifiers defined in this same file.
    Used to detect relative module paths like `withdraw_utils::foo`
    and prefix them with the file module path.
    """
    mods = set()
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "mod_item":
            mid = find_child_of_type(n, "identifier")
            if mid:
                mods.add(node_text(code_bytes, mid))
        stack.extend(n.children)
    return mods

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

# ------------------------------------------------------------
# File processing
# ------------------------------------------------------------
def process_repository(input_paths):
    rust_files = find_rust_files(input_paths)
    if not rust_files:
        print("❗ No .rs files found to process.")
        sys.exit(1)

    output_dir = "output_results"
    os.makedirs(output_dir, exist_ok=True)

    # ---- REPO PASS 1: per-file scans and repo-wide accumulation ----
    per_file_direct_and_legacy = {}  # file_path -> hits (direct + legacy)
    per_file_ast_name = {}           # file_path -> ast file name

    # repo accumulators
    repo_wrapper_fn_qnames = set()
    repo_wrapper_method_names = set()
    repo_edges_fn = []
    repo_edges_meth = []
    repo_func_meta = {}  # qname -> meta

    for file_path in rust_files:
        res = file_pass1_scan(file_path, output_dir)

        per_file_direct_and_legacy[file_path] = res['hits_direct_and_legacy']
        per_file_ast_name[file_path] = res['ast_file']

        repo_wrapper_fn_qnames |= set(res['wrapper_fn_qnames_local'])
        repo_wrapper_method_names |= set(res['wrapper_method_names_local'])
        repo_edges_fn.extend(res['edges_fn'])
        repo_edges_meth.extend(res['edges_meth'])
        # merge func_meta
        for q, meta in res['func_meta'].items():
            repo_func_meta[q] = meta

    # ---- REPO WRAPPER PROPAGATION (fixpoint) ----
    repo_wrapper_fn_qnames, repo_wrapper_method_names = propagate_wrappers_repo_wide(
        repo_wrapper_fn_qnames, repo_wrapper_method_names,
        repo_edges_fn, repo_edges_meth,
        repo_func_meta
    )
    print(repo_wrapper_fn_qnames)
    # ---- REPO PASS 2: tag wrapper_cpi callsites using global wrapper sets ----
    summary = {}
    grand_totals = {}
    for file_path in rust_files:
        wrapper_hits = file_pass2_tag_wrappers(file_path, repo_wrapper_fn_qnames, repo_wrapper_method_names,repo_func_meta)

        # combine hits: direct+legacy (from pass1) + wrapper (now)
        hits = list(per_file_direct_and_legacy[file_path]) + list(wrapper_hits)
        hits.sort(key=lambda h: (h['line'], h['col']))

        # totals
        counts = {}
        for h in hits:
            k = h['kind']
            counts[k] = counts.get(k, 0) + 1

        # clean total: do NOT count legacy invoke kinds to avoid double-count
        total_cpi = (
            counts.get('direct_cpi', 0)
            + counts.get('wrapper_cpi', 0)
            + counts.get('anchor_cpi_helper', 0)
            + counts.get('anchor_cpi_helper_wrapped', 0)
        )

        result = {
            'ast_file': per_file_ast_name[file_path],
            'hits': hits,
            'totals': {**counts, 'total_cpi': total_cpi},
        }
        summary[file_path] = result

        for k, v in result['totals'].items():
            grand_totals[k] = grand_totals.get(k, 0) + v

    return summary, grand_totals, output_dir

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
    summary, grand_totals, output_dir = process_repository(input_paths)

    summary_path = os.path.join(output_dir, 'cpi_summary.json')
    with open(summary_path, 'w', encoding='utf-8') as json_file:
        json.dump({
            'files': summary,
            'global_totals': grand_totals
        }, json_file, indent=2, ensure_ascii=False)

    print(f"\n✅ CPI summary written to {summary_path}")

if __name__ == "__main__":
    main()
