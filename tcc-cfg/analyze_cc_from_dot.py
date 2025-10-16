import os
import sys
import re
import json
import csv
import collections

# --- Cyclomatic Complexity calculator for MIR .dot files ---

def calculate_cc_from_dot(filepath):
    """Compute McCabe's Cyclomatic Complexity = E - N + 2P for a single MIR .after.dot file."""
    # Only match MIR basic blocks (nodes starting with 'bb') and control-flow edges between them
    node_def_re = re.compile(r'^\s*(bb[^\s\[]+)\s*\[', re.MULTILINE)
    edge_re = re.compile(r'^\s*(bb[^\s\[]+)\s*->\s*(bb[^\s\[]+)', re.MULTILINE)
    abs_path = os.path.abspath(filepath)

    with open(filepath, 'r', encoding='utf-8') as f:
        text = f.read()

    nodes = set()
    edges = set()

    # 1) Detect node definitions (basic blocks)
    for m in node_def_re.finditer(text):
        nodes.add(m.group(1))

    # 2) Detect edges (control-flow links between basic blocks)
    for m in edge_re.finditer(text):
        src, dst = m.group(1), m.group(2)
        edges.add((src, dst))
        # Ensure both endpoints are included in the node set
        nodes.add(src)
        nodes.add(dst)

    # 3) Compute P = number of connected components
    def count_components(nodes_set, edges_set):
        """Compute how many connected components exist in the CFG."""
        if not nodes_set:
            return 0

        # Build adjacency list
        adj = collections.defaultdict(set)
        for s, d in edges_set:
            adj[s].add(d)
            adj[d].add(s)  # Undirected edges for component counting

        visited = set()
        components = 0

        for n in nodes_set:
            if n in visited:
                continue
            components += 1
            stack = [n]
            while stack:
                u = stack.pop()
                if u in visited:
                    continue
                visited.add(u)
                for v in adj[u]:
                    if v not in visited:
                        stack.append(v)
        return components

    P = count_components(nodes, edges)
    if P == 0 and nodes:
        P = 1  # Safety: at least 1 component if nodes exist

    N = len(nodes)
    E = len(edges)
    cc = E - N + 2 * max(P, 1) if N > 0 else 0

    return max(cc, 1)


def analyze_folder(folder_path):
    """Compute total CC for all .dot files in a folder."""
    results = {}
    total_cc = 0

    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".after.dot"):
                file_path = os.path.join(root, file)
                cc_value = calculate_cc_from_dot(file_path)
                results[file] = {"total_tcc": cc_value}
                total_cc += cc_value

    results["total_repo_tcc"] = total_cc
    return results


def save_results_to_csv(results, output_csv):
    """Save results to CSV file (excluding total_repo_tcc)."""
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        # Write headers
        writer.writerow(["File .dot", "New Tcc"])

        # Write each entry except total_repo_tcc
        for filename, data in results.items():
            if filename == "total_repo_tcc":
                continue
            writer.writerow([filename, data["total_tcc"]])


def main():
    """Entry point: read folder path, analyze, and save JSON + CSV."""
    if len(sys.argv) < 2:
        print("Usage: python analyze_cc_from_dot.py <path_to_mir_dump>")
        sys.exit(1)

    folder_path = sys.argv[1]
    if not os.path.isdir(folder_path):
        print(f"Error: {folder_path} is not a valid directory.")
        sys.exit(1)

    # Analyze all files
    cc_summary = analyze_folder(folder_path)

    # Save JSON
    output_json = "cc_summary.json"
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(cc_summary, f, indent=2)

    # Save CSV
    output_csv = "cc_summary.csv"
    save_results_to_csv(cc_summary, output_csv)

    print(f"✅ Cyclomatic complexity results saved to:")
    print(f"   - {output_json}")
    print(f"   - {output_csv}")


if __name__ == "__main__":
    main()
