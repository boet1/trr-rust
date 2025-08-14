import os
import json
import sys
from tree_sitter import Language, Parser
import tree_sitter_rust as tsrust

# Initialize Rust language parser
RUST_LANGUAGE = Language(tsrust.language())
parser = Parser(RUST_LANGUAGE)

# Node types considered as decision points for Cyclomatic Complexity (TCC)
DECISION_NODES = {
    'if_expression', 'for_expression', 'while_expression',
    'loop_expression', 'match_arm',
    'try_expression', 'closure_expression', '&&', '||'
}

def read_rust_code(file_path):
    """Reads Rust code from the provided file path."""
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return code, code.encode('utf8')

def collect_ast_lines(node, indent=""):
    """Collects all AST nodes as indented text lines."""
    lines = [f"{indent}{node.type} ({node.start_point} - {node.end_point})"]
    for child in node.children:
        lines.extend(collect_ast_lines(child, indent + "  "))
    return lines

def count_decision_points(node):
    """Recursively counts decision points within a node."""
    count = 1 if node.type in DECISION_NODES else 0
    for child in node.children:
        count += count_decision_points(child)
    return count

def extract_functions(node, code_bytes):
    """
    Extracts only functions (not closures), and computes TCC
    including all decision points and closures inside them.
    """
    functions = []
    if node.type == 'function_item':
        # Get function name
        function_name = next(
            (code_bytes[child.start_byte:child.end_byte].decode('utf8')
             for child in node.children if child.type == 'identifier'), None
        )
        tcc = count_decision_points(node) + 1
        functions.append({'name': function_name, 'tcc': tcc})

    for child in node.children:
        functions.extend(extract_functions(child, code_bytes))
    return functions

def process_file(file_path, output_dir):
    """Processes a Rust file, exporting AST and TCC data."""
    print(f"🔎 Processing file: {file_path}")
    code_str, code_bytes = read_rust_code(file_path)
    tree = parser.parse(code_bytes)
    root_node = tree.root_node

    # Write AST to .txt file
    ast_lines = collect_ast_lines(root_node)
    ast_file_name = os.path.basename(file_path).replace('.rs', '_ast.txt')
    ast_output_path = os.path.join(output_dir, ast_file_name)

    with open(ast_output_path, 'w') as ast_file:
        ast_file.write('\n'.join(ast_lines))

    print(f"✅ AST written to {ast_output_path}")

    # Extract TCC from functions only
    functions_tcc = extract_functions(root_node, code_bytes)
    total_tcc = sum(f['tcc'] for f in functions_tcc)

    return {
        'functions': functions_tcc,
        'total_tcc': total_tcc,
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

    # Write the summary JSON with all TCC data
    summary_path = os.path.join(output_dir, 'tcc_summary.json')
    with open(summary_path, 'w') as json_file:
        json.dump(summary, json_file, indent=2)

    print(f"\n✅ TCC summary written to {summary_path}")

if __name__ == "__main__":
    main()
