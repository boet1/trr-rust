import os
import json
import sys
from tree_sitter import Language, Parser
import tree_sitter_rust as tsrust

# Initialize Rust language parser
RUST_LANGUAGE = Language(tsrust.language())
parser = Parser(RUST_LANGUAGE)

# Decision points for TDP (Solidity-style: only structural control nodes)
# We WILL count:
#   - if_expression (+1) and +1 more if it has an 'else' (alternative)
#   - while_expression (+1)
#   - for_expression (+1)
#   - loop_expression (+1)
#   - each match_arm (+1)
#   - try_expression ('?' operator) (+1)
#   - panic-like macros (panic!, assert!, assert_eq!, assert_ne!, debug_assert!,
#     debug_assert_eq!, debug_assert_ne!, unreachable!, todo!, unimplemented!) (+1)
DECISION_NODE_TYPES = {
    'if_expression',
    'while_expression',
    'for_expression',
    'loop_expression',
    'match_arm',
    'try_expression'
    # IMPORTANT: do NOT include 'macro_invocation' here to avoid double counting
}

# Macros that abort execution (similar to require/assert/revert in Solidity)
PANIC_LIKE_MACROS = {
    'panic',
    'assert', 'assert_eq', 'assert_ne',
    'debug_assert', 'debug_assert_eq', 'debug_assert_ne',
    'unreachable', 'todo', 'unimplemented',
}

def read_rust_code(file_path):
    """Reads Rust code from the provided file path."""
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return code, code.encode('utf8')

def collect_ast_lines(node, indent=""):
    """Collects all AST nodes as indented text lines (for debug/inspection)."""
    lines = [f"{indent}{node.type} ({node.start_point} - {node.end_point})"]
    for child in node.children:
        lines.extend(collect_ast_lines(child, indent + "  "))
    return lines

def is_panic_macro(node, code_bytes):
    """
    Returns True if node is a macro_invocation whose identifier is in PANIC_LIKE_MACROS.
    Grammar exposes this as a macro_invocation; the identifier text equals macro name.
    """
    if node.type != 'macro_invocation':
        return False

    # Depending on grammar version, the identifier may be a direct child or a named field.
    # Try common access patterns safely:
    # 1) child_by_field_name('macro') or 'name'
    for field in ('macro', 'name'):
        ident = node.child_by_field_name(field)
        if ident is not None:
            text = code_bytes[ident.start_byte:ident.end_byte].decode('utf8')
            return text in PANIC_LIKE_MACROS

    # 2) Fallback: find first identifier child
    for ch in node.children:
        if ch.type == 'identifier':
            text = code_bytes[ch.start_byte:ch.end_byte].decode('utf8')
            return text in PANIC_LIKE_MACROS

    return False

def count_decision_points(node, code_bytes):
    """
    Recursively counts decision points (TDP) within a node.
    - Counts only structural control nodes (see DECISION_NODE_TYPES).
    - Adds +1 for 'else' when an if_expression has an 'alternative'.
    - Counts panic-like macros by detecting macro_invocation whose identifier is in PANIC_LIKE_MACROS.
    """
    count = 0

    # Base count for listed decision node types
    if node.type in DECISION_NODE_TYPES:
        count += 1

    # Special handling: panic-like macros (panic!/assert!/unreachable!/todo!/...)
    if node.type == 'macro_invocation' and is_panic_macro(node, code_bytes):
        count += 1

    # Recurse
    for child in node.children:
        count += count_decision_points(child, code_bytes)

    return count

def extract_functions(node, code_bytes):
    """
    Extracts only top-level functions (function_item) and computes TDP inside each.
    - Counts decision points inside closures as part of the parent function (no separate unit).
    """
    functions = []
    if node.type == 'function_item':
        # Get function name
        function_name = next(
            (code_bytes[child.start_byte:child.end_byte].decode('utf8')
             for child in node.children if child.type == 'identifier'),
            None
        )
        tdp = count_decision_points(node, code_bytes)
        functions.append({'name': function_name, 'tdp': tdp})

    for child in node.children:
        functions.extend(extract_functions(child, code_bytes))
    return functions

def process_file(file_path, output_dir):
    """Processes a Rust file, exporting AST and TDP data."""
    print(f"🔎 Processing file: {file_path}")
    code_str, code_bytes = read_rust_code(file_path)
    tree = parser.parse(code_bytes)
    root_node = tree.root_node

    # Write AST to .txt file
    ast_lines = collect_ast_lines(root_node)
    ast_file_name = os.path.basename(file_path).replace('.rs', '_ast.txt')
    ast_output_path = os.path.join(output_dir, ast_file_name)

    with open(ast_output_path, 'w', encoding='utf-8') as ast_file:
        ast_file.write('\n'.join(ast_lines))

    print(f"✅ AST written to {ast_output_path}")

    # Extract TDP per function
    functions_tdp = extract_functions(root_node, code_bytes)
    total_tdp = sum(f['tdp'] for f in functions_tdp)

    return {
        'functions': functions_tdp,
        'total_tdp': total_tdp,
        'ast_file': ast_file_name
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

    # Process each Rust file
    for file_path in rust_files:
        result = process_file(file_path, output_dir)
        summary[file_path] = result

    # Write the summary JSON with all TDP data
    summary_path = os.path.join(output_dir, 'tdp_summary.json')
    with open(summary_path, 'w', encoding='utf-8') as json_file:
        json.dump(summary, json_file, indent=2)

    print(f"\n✅ TDP summary written to {summary_path}")

if __name__ == "__main__":
    main()
