import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime


def find_rust_files(paths):
    """Finds all .rs files in provided paths (files or directories)."""
    rust_files = []
    for path in paths:
        if os.path.isfile(path) and path.endswith('.rs'):
            rust_files.append(os.path.abspath(path))
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith('.rs'):
                        rust_files.append(os.path.abspath(os.path.join(root, file)))
    # De-duplicate while preserving order
    seen = set()
    uniq = []
    for p in rust_files:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def run_cloc_by_file(paths):
    """
    Run cloc with --by-file for the provided paths.
    Returns a dict: { absolute_file_path: sloc_code_int }
    If cloc is not installed or output is unparseable, returns (False, {}).
    """
    # Pass native paths to cloc (avoid forcing POSIX separators here)
    native_paths = [str(Path(p)) for p in paths]
    cmd = ["cloc", *native_paths, "--include-ext=rs", "--by-file", "--json", "--quiet"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        return False, {}
    except subprocess.CalledProcessError as e:
        # cloc ran but failed; treat as not usable
        sys.stderr.write(f"[cloc] Error: {e.stderr or e.stdout}\n")
        return False, {}

    out = proc.stdout.strip()
    # cloc may print non-JSON lines; try to isolate the JSON object
    start = out.find("{")
    end = out.rfind("}")
    if start == -1 or end == -1:
        sys.stderr.write("[cloc] Could not parse JSON output.\n")
        return False, {}

    raw = out[start:end+1]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        sys.stderr.write("[cloc] Invalid JSON output.\n")
        return False, {}

    sloc_map = {}

    # Case 1: data["files"] is a dict keyed by filename
    files_obj = data.get("files")
    if isinstance(files_obj, dict):
        for fname, stats in files_obj.items():
            try:
                lang = (stats.get("language") or "").lower()
                if lang == "rust":
                    sloc_map[Path(fname).resolve().as_posix()] = int(stats.get("code", 0))
            except Exception:
                continue
    # Case 2: data["files"] is a list of objects with filename/code
    elif isinstance(files_obj, list):
        for item in files_obj:
            fname = item.get("filename") or item.get("file") or item.get("name")
            if not fname:
                continue
            lang = (item.get("language") or "").lower()
            if lang != "rust":
                continue
            try:
                sloc_map[Path(fname).resolve().as_posix()] = int(item.get("code", 0))
            except Exception:
                continue
    else:
        # Case 3: Top-level file entries (common in cloc 1.9x with --by-file)
        # Skip known non-file keys like "header" and "SUM"
        for key, val in data.items():
            if key in ("header", "SUM"):
                continue
            if not isinstance(val, dict):
                continue
            # We accept either explicit Rust language or .rs extension
            lang = (val.get("language") or "").lower()
            if lang and lang != "rust":
                continue
            if not key.endswith(".rs") and not lang:
                continue
            code = val.get("code")
            if isinstance(code, int):
                sloc_map[Path(key).resolve().as_posix()] = code

    return True, sloc_map


def count_tokens_whitespace(file_path):
    """Count whitespace-separated tokens using len(text.split())."""
    try:
        text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        with open(file_path, "rb") as f:
            text = f.read().decode("utf-8", errors="ignore")
    return len(text.split())


def main():
    parser = argparse.ArgumentParser(description="Analyze Rust tokens and SLOC per file (SLOC via cloc if available).")
    parser.add_argument("paths", nargs="+", help="One or more paths (files or directories). Example: ../src/")
    parser.add_argument("--output-dir", default="output_results", help="Directory to write JSON output (default: output_results)")
    args = parser.parse_args()

    # Normalize incoming paths
    input_paths = [Path(p).resolve() for p in args.paths]

    # Find .rs files
    rs_files = find_rust_files([str(p) for p in input_paths])

    # Token counts
    token_map = {Path(p).resolve().as_posix(): count_tokens_whitespace(p) for p in rs_files}

    # SLOC via cloc (only if installed)
    cloc_ok, sloc_map = run_cloc_by_file([str(p) for p in input_paths])
    if not cloc_ok:
        sys.stderr.write("[info] 'cloc' no está instalado o falló su ejecución. No se calculará sLoc.\n")

    # Prepare result JSON
    result = {"files": {}}
    for fpath in rs_files:
        key = Path(fpath).resolve().as_posix()
        result["files"][key] = {
            "total_token": int(token_map.get(key, 0)),
            "sLoc": (int(sloc_map[key]) if cloc_ok and key in sloc_map else None)
        }

    # Metadata
    result["_meta"] = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "paths_scanned": [p.as_posix() for p in input_paths],
        "cloc_used": bool(cloc_ok),
        "note": (None if cloc_ok else "sLoc no calculado por falta de 'cloc' o error al ejecutarlo.")
    }

    # Write output
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "rust_tokens_sloc.json"
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(f"JSON escrito en: {out_file}")


if __name__ == "__main__":
    main()
