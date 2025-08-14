import os
import json
import sys
from tree_sitter import Language, Parser
import tree_sitter_rust as tsrust

# Initialize Rust language parser
RUST_LANGUAGE = Language(tsrust.language())
parser = Parser(RUST_LANGUAGE)

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

# ------------------------------------------------------------
# CPI detection
# ------------------------------------------------------------

def classify_call_expr(call_node, code_bytes):
    """
    Given a call_expression node, classify it as one of:
      - invoke
      - invoke_signed
      - anchor_cpi_helper
      - method_invoke
      - method_invoke_signed
    Or return None if not a CPI site.
    """
    # In Rust grammar, call_expression has a "function" child which can be:
    #   - identifier
    #   - scoped_identifier  (e.g., anchor_spl::token::cpi::transfer)
    #   - field_expression   (method call: obj.method)
    # Depending on bindings, we may not have field names; so we search by types.
    func = None
    for ch in call_node.children:
        if ch.type in ('identifier', 'scoped_identifier', 'field_expression'):
            func = ch
            break
    if func is None:
        return None

    if func.type == 'identifier':
        name = node_text(code_bytes, func).encode('utf8')
        if is_ident_invoke(name):
            return 'invoke', func
        if is_ident_invoke_signed(name):
            return 'invoke_signed', func
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
        return None

    return None

def walk_calls_and_collect(node, code_str, code_bytes, hits):
    """Recursively traverse the AST and collect CPI hits."""
    if node.type == 'call_expression':
        res = classify_call_expr(node, code_bytes)
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
        walk_calls_and_collect(ch, code_str, code_bytes, hits)

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
    walk_calls_and_collect(root, code_str, code_bytes, hits)

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
