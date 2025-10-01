import argparse
import json
import re
import shutil
from pathlib import Path
from typing import List, Tuple, Dict, Any

from tree_sitter import Language, Parser
import tree_sitter_rust as tsrust

# Initialize Rust language parser (as requested)
RUST_LANGUAGE = Language(tsrust.language())
parser = Parser(RUST_LANGUAGE)

# ---------- Helpers for AST traversal ----------

def iter_nodes_preorder(root):
    """Yield nodes in pre-order traversal using a Tree-sitter cursor."""
    cursor = root.walk()
    stack = [cursor.node]
    while stack:
        node = stack.pop()
        yield node
        for child in reversed(node.children):
            stack.append(child)

def node_text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

def is_inner_cfg_test(text: str) -> bool:
    """Detect inner attribute that marks the entire file/module as test-only: #![cfg(test)]"""
    t = "".join(text.split())
    return t.startswith("#![cfg(test)]")

def is_attribute_test_like(text: str) -> bool:
    """
    True only for:
      - #[test]
      - #[cfg(test)]
    """
    t = "".join(text.split())  # strip all spaces for robust matching
    if t.startswith("#!"):  # inner attribute handled separately
        return False
    return t.startswith("#[test]") or t.startswith("#[cfg(test)]")

def is_rust_item(node_type: str) -> bool:
    """Conservative list of Rust items we might remove after a test attribute."""
    return node_type in {
        "function_item",
        "mod_item"
    }

# ---------- Core logic ----------

def compute_removal_spans(src: str, root) -> List[Tuple[int, int]]:
    """
    Find byte spans to remove:
    1) If an inner attribute #![cfg(test)] exists at file level -> remove whole file.
    2) Group consecutive *outer* attributes; if any is test-like, remove from the FIRST attribute
       through the END of the next item node. If there is no following item, remove only the attributes.
    """
    source_bytes = src.encode("utf-8", errors="replace")
    spans: List[Tuple[int, int]] = []

    # 1) Inner attribute at top (#![cfg(test)]) -> remove entire file
    for n in iter_nodes_preorder(root):
        if n.type in ("inner_attribute_item", "attribute_item"):
            txt = node_text(source_bytes, n)
            if is_inner_cfg_test(txt):
                return [(0, len(source_bytes))]
        # Stop scanning early if we've gone past the top-level attribute area
        if n.parent and n.parent.type not in ("source_file", "mod_item"):
            # once we dip into function bodies etc, we can break the inner-attr quick check
            break

    # 2) Group outer attributes and remove from first attribute to end of next item
    nodes = list(iter_nodes_preorder(root))
    i = 0
    N = len(nodes)

    while i < N:
        n = nodes[i]
        if n.type == "attribute_item":
            group_attrs = [n]
            j = i + 1
            # Gather consecutive attributes
            while j < N and nodes[j].type == "attribute_item":
                group_attrs.append(nodes[j])
                j += 1

            # Next significant item after attributes
            k = j
            while k < N and not is_rust_item(nodes[k].type):
                k += 1

            any_test_like = any(is_attribute_test_like(node_text(source_bytes, a)) for a in group_attrs)

            if any_test_like:
                first_attr_start = group_attrs[0].start_byte
                last_attr_end = group_attrs[-1].end_byte

                if k < N:
                    item_node = nodes[k]
                    # Remove from FIRST attribute to END of the item (kills tags + block)
                    spans.append((first_attr_start, item_node.end_byte))
                    i = k + 1
                    continue
                else:
                    # No following item -> remove the attributes themselves
                    spans.append((first_attr_start, last_attr_end))
                    i = j
                    continue
            else:
                i = j
                continue
        else:
            i += 1

    # Merge overlapping spans
    if not spans:
        return spans
    spans.sort(key=lambda t: t[0])
    merged = [spans[0]]
    for s, e in spans[1:]:
        ls, le = merged[-1]
        if s <= le:
            merged[-1] = (ls, max(le, e))
        else:
            merged.append((s, e))
    return merged

def remove_spans(src: str, spans: List[Tuple[int, int]]) -> str:
    if not spans:
        return src
    b = src.encode("utf-8", errors="replace")
    out = []
    last = 0
    for s, e in spans:
        out.append(b[last:s])
        last = e
    out.append(b[last:])
    return b"".join(out).decode("utf-8", errors="replace")

def sanitize_rust_code(source_code: str) -> str:
    tree = parser.parse(source_code.encode("utf-8", errors="replace"))
    root = tree.root_node
    spans = compute_removal_spans(source_code, root)
    return remove_spans(source_code, spans)


RE_ATTR_REPORT = re.compile(r"#\s*\[\s*(?:cfg\s*\(\s*test\s*\)|test)\s*\]", re.IGNORECASE)

def collect_report_entries(file_path: Path, text: str):
    out = []
    for idx, line in enumerate(text.splitlines(keepends=False), start=1):
        for m in RE_ATTR_REPORT.finditer(line):
            raw = m.group(0)
            label = "cfg(test)" if "cfg" in raw.lower() else "test"
            out.append({
                "file": str(file_path),
                "attribute": label,
                "line": idx,
                "line_text": line.rstrip()
            })
    return out


# ---------- I/O & orchestration ----------

def sanitize_file(in_path: Path, out_path: Path, report_accum: List[Dict[str, Any]]):
    try:
        text = in_path.read_text(encoding="utf-8", errors="replace")

        # 1) Collect report entries BEFORE sanitization
        report_accum.extend(collect_report_entries(in_path, text))

        # 2) Sanitize
        cleaned = sanitize_rust_code(text)

        # 3) Write output
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(cleaned, encoding="utf-8")
    except Exception as e:
        print(f"[ERROR] {in_path}: {e}")

def copy_other_file(in_path: Path, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(in_path, out_path)

def sanitize_folder(src_root: Path, out_root: Path, report_accum: List[Dict[str, Any]]):
    """
    For one input folder:
    - Write sanitized .rs files under out_root/<src_root.name>/...
    - Copy non-.rs files as-is (useful to keep project buildable).
    """
    base_out = out_root / src_root.name
    for p in src_root.rglob("*"):
        rel = p.relative_to(src_root)
        dst = base_out / rel
        if p.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            continue
        if p.suffix == ".rs":
            sanitize_file(p, dst, report_accum)
        else:
            copy_other_file(p, dst)

def main():
    ap = argparse.ArgumentParser(description="Sanitize Rust projects by removing test-only code blocks and reporting attributes.")
    ap.add_argument("directories", nargs="+", help="One or more folders to sanitize recursively.")
    ap.add_argument("-o", "--output", default="sanitized_output", help="Output root directory.")
    ap.add_argument("-r", "--report", default="found_test_attributes.json", help="JSON report file path.")
    args = ap.parse_args()

    out_root = Path(args.output)
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    report_accum: List[Dict[str, Any]] = []

    for d in args.directories:
        src_root = Path(d)
        if not src_root.exists() or not src_root.is_dir():
            print(f"[SKIP] Not a directory: {src_root}")
            continue
        sanitize_folder(src_root, out_root, report_accum)
        print(f"[OK] Sanitized: {src_root} -> {out_root/src_root.name}")

    # Write JSON report (all folders aggregated)
    with Path(args.report).open("w", encoding="utf-8") as f:
        json.dump(report_accum, f, indent=2, ensure_ascii=False)

    print(f"\nDone.\n- Sanitized output at: {out_root.resolve()}\n- Report written to: {Path(args.report).resolve()}")

if __name__ == "__main__":
    main()
