import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Tuple, Iterable

# --- Configuration ---
MODULE_DIRS = ["ats", "tcc", "tdp", "tec"]
SCRIPT_NAMES = {m: f"{m}.py" for m in MODULE_DIRS}
OUTPUT_SUBDIR = "output_results"
CSV_FILENAME = "metrics_summary.csv"

CSV_COLUMNS = ["File", "sLOC", "Token", "TCC", "TDP", "TEC(total_cpi)"]


# --- Helpers ---

def log(msg: str) -> None:
    print(f"[main] {msg}")

def safe_rmtree_contents(dir_path: Path) -> None:
    """
    Delete all contents of a directory if it exists, keeping the directory itself.
    """
    if not dir_path.exists() or not dir_path.is_dir():
        return
    for item in dir_path.iterdir():
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            try:
                item.unlink()
            except FileNotFoundError:
                pass

def discover_repo_root() -> Path:
    """
    Repo root is the directory where this main.py resides (expected to contain ats/tcc/tdp/tec).
    """
    return Path(__file__).resolve().parent

def run_module_script(module_dir: Path, script_name: str, target_dir: Path) -> Tuple[int, str, str]:
    """
    Run a module script like ats.py, tcc.py, tdp.py, tec.py with the target_dir argument.
    Executes with cwd=module_dir so relative outputs land in module_dir/output_results.
    Returns (returncode, stdout, stderr).
    """
    script_path = module_dir / script_name
    if not script_path.exists():
        return (127, "", f"Script not found: {script_path}")
    cmd = [sys.executable, str(script_path), str(target_dir)]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            cwd=str(module_dir),  # <<< important: run inside the module folder
        )
        return (proc.returncode, proc.stdout, proc.stderr)
    except Exception as e:
        return (1, "", f"Error running {script_path}: {e}")

def iter_json_files(output_dir: Path) -> Iterable[Path]:
    if output_dir.exists() and output_dir.is_dir():
        yield from output_dir.rglob("*.json")

def normalize_file_key(file_key: str, analyze_dir: Path) -> str:
    """
    Normalize per-file keys from JSON into absolute paths for internal merging.
    """
    fk = file_key.strip().strip('"').strip("'")
    p = Path(fk)
    if not p.is_absolute():
        p = (analyze_dir / p).resolve()
    else:
        p = p.resolve()
    return str(p)

def extract_from_ats(json_obj: Dict[str, Any], analyze_dir: Path) -> Dict[str, Dict[str, Any]]:

    results: Dict[str, Dict[str, Any]] = {}
    files = json_obj.get("files")
    if isinstance(files, dict):
        for file_key, data in files.items():
            if isinstance(data, dict):
                path = normalize_file_key(file_key, analyze_dir)
                token = data.get("total_token")
                sloc = data.get("sLoc")
                row: Dict[str, Any] = {}
                if sloc is not None:
                    row["sLOC"] = sloc
                if token is not None:
                    row["Token"] = token
                if row:
                    results[path] = row
    return results

def extract_from_tcc_or_tdp(json_obj: Dict[str, Any], analyze_dir: Path, key_name: str) -> Dict[str, Dict[str, Any]]:

    results: Dict[str, Dict[str, Any]] = {}
    if isinstance(json_obj, dict):
        for file_key, data in json_obj.items():
            if not isinstance(data, dict):
                continue
            path = normalize_file_key(file_key, analyze_dir)
            val = data.get(key_name)
            if val is not None:
                out_key = "TCC" if key_name == "total_tcc" else "TDP"
                results[path] = {out_key: val}
    return results

def extract_from_tec(json_obj: Dict[str, Any], analyze_dir: Path) -> Dict[str, Dict[str, Any]]:

    results: Dict[str, Dict[str, Any]] = {}
    files = json_obj.get("files")
    if isinstance(files, dict):
        for file_key, data in files.items():
            if not isinstance(data, dict):
                continue
            totals = data.get("totals", {})
            if isinstance(totals, dict):
                total_cpi = totals.get("total_cpi")
                if total_cpi is not None:
                    path = normalize_file_key(file_key, analyze_dir)
                    results[path] = {"TEC(total_cpi)": total_cpi}
    return results

def parse_single_json(path: Path, analyze_dir: Path) -> Dict[str, Dict[str, Any]]:
    """
    Infer tool by schema and extract metrics.
    Returns: { abs_file_path: {col: value, ...}, ... }
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:
        log(f"Skipping invalid JSON {path}: {e}")
        return {}

    if isinstance(obj, dict) and "files" in obj:
        files_val = obj.get("files", {})
        # TEC has nested "totals"
        if any(isinstance(v, dict) and "totals" in v for v in files_val.values()):
            return extract_from_tec(obj, analyze_dir)
        else:
            return extract_from_ats(obj, analyze_dir)

    if isinstance(obj, dict):
        if any(isinstance(v, dict) and "total_tcc" in v for v in obj.values()):
            return extract_from_tcc_or_tdp(obj, analyze_dir, "total_tcc")
        if any(isinstance(v, dict) and "total_tdp" in v for v in obj.values()):
            return extract_from_tcc_or_tdp(obj, analyze_dir, "total_tdp")

    return {}

def merge_metrics(dest: Dict[str, Dict[str, Any]], src: Dict[str, Dict[str, Any]]) -> None:
    for file_path, metrics in src.items():
        if file_path not in dest:
            dest[file_path] = {}
        dest[file_path].update(metrics)

def path_after_anchor(abs_path: str, anchor_dir: Path) -> str:
    """
    Return the path portion that comes after the anchor_dir (e.g., after .../src/).
    If abs_path is not inside anchor_dir, try to cut after the last '<anchor_name>/'.
    Fallback to basename.
    """
    p = Path(abs_path)
    try:
        rel = p.relative_to(anchor_dir)
        return rel.as_posix()
    except Exception:
        # Fallback: cut after "<anchor_name>/" occurrence anywhere in the string
        anchor = anchor_dir.name  # e.g., "src"
        s = str(p)
        needle = f"{os.sep}{anchor}{os.sep}"
        idx = s.rfind(needle)
        if idx != -1:
            return s[idx + len(needle):].replace(os.sep, "/")
        return p.name

def write_csv(rows_by_file: Dict[str, Dict[str, Any]], csv_path: Path, anchor_dir: Path) -> None:

    """
    Write the CSV using only the filename (basename) in the 'File' column.
    If two different files share the same name in different directories,
    they will appear as separate rows with the same 'File' value.
    """
    files_sorted = sorted(rows_by_file.keys())
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for abs_path in files_sorted:
            data = rows_by_file[abs_path]
            display_path = path_after_anchor(abs_path, anchor_dir)
            row = {
                "File": display_path,
                "sLOC": data.get("sLOC"),
                "Token": data.get("Token"),
                "TCC": data.get("TCC"),
                "TDP": data.get("TDP"),
                "TEC(total_cpi)": data.get("TEC(total_cpi)"),
            }
            writer.writerow(row)

def clean_outputs(repo_root: Path) -> None:
    """
    Ensure each module's output_results is empty and present.
    """
    for module in MODULE_DIRS:
        out_dir = repo_root / module / OUTPUT_SUBDIR
        if out_dir.exists():
            log(f"Cleaning: {out_dir}")
            safe_rmtree_contents(out_dir)
        else:
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

def relocate_orphan_outputs(repo_root: Path, module_dir: Path) -> None:
    """
    If a tool wrote to repo_root/output_results by mistake, move its contents
    into module_dir/output_results.
    """
    orphan = repo_root / OUTPUT_SUBDIR
    if not orphan.exists() or not orphan.is_dir():
        return
    target = module_dir / OUTPUT_SUBDIR
    target.mkdir(parents=True, exist_ok=True)

    moved_any = False
    for item in list(orphan.iterdir()):
        try:
            shutil.move(str(item), str(target / item.name))
            moved_any = True
        except Exception as e:
            log(f"Could not move {item} -> {target}: {e}")

    # Remove orphan directory if empty
    try:
        if not any(orphan.iterdir()):
            orphan.rmdir()
    except Exception:
        pass

    if moved_any:
        log(f"Relocated stray outputs from {orphan} to {target}")

def run_all_modules(repo_root: Path, analyze_dir: Path) -> None:
    """
    Run each module from within its own directory (cwd=module_dir) and
    relocate stray outputs if any were created at repo_root/output_results.
    """
    for module in MODULE_DIRS:
        module_dir = repo_root / module
        script_name = SCRIPT_NAMES[module]
        log(f"Running {module}/{script_name} on {analyze_dir} ...")
        code, out, err = run_module_script(module_dir, script_name, analyze_dir)
        if out.strip():
            log(f"{module} stdout:\n{out}")
        if err.strip():
            log(f"{module} stderr:\n{err}")
        if code != 0:
            log(f"⚠️  {module} exited with code {code}. Continuing.")
        # Safety net: pull any stray 'output_results' at repo root into the module
        relocate_orphan_outputs(repo_root, module_dir)

def collect_jsons(repo_root: Path, analyze_dir: Path) -> Dict[str, Dict[str, Any]]:
    aggregated: Dict[str, Dict[str, Any]] = {}
    for module in MODULE_DIRS:
        output_dir = repo_root / module / OUTPUT_SUBDIR
        if not output_dir.exists():
            continue
        for jf in iter_json_files(output_dir):
            parsed = parse_single_json(jf, analyze_dir)
            if parsed:
                merge_metrics(aggregated, parsed)
    return aggregated

def main():
    parser = argparse.ArgumentParser(
        description="Run ats/tcc/tdp/tec, parse produced JSONs, build a unified CSV."
    )
    parser.add_argument("target_dir", help="Directory to analyze (passed into ats/tcc/tdp/tec)")
    args = parser.parse_args()

    analyze_dir = Path(args.target_dir).resolve()
    if not analyze_dir.exists() or not analyze_dir.is_dir():
        log(f"ERROR: target_dir does not exist or is not a directory: {analyze_dir}")
        sys.exit(2)

    repo_root = discover_repo_root()
    log(f"Repo root: {repo_root}")
    log(f"Analyze dir: {analyze_dir}")

    # 1) Clean outputs
    clean_outputs(repo_root)

    # 2) Run modules (with per-module CWD + stray relocation)
    run_all_modules(repo_root, analyze_dir)

    # 3) Parse JSONs
    log("Parsing generated JSONs ...")
    rows_by_file = collect_jsons(repo_root, analyze_dir)

    # 4) Write CSV
    if not rows_by_file:
        log("⚠️  No results found. Did the tools write JSONs to output_results/?")
    else:
        csv_path = Path.cwd() / CSV_FILENAME
        write_csv(rows_by_file, csv_path, analyze_dir)
        log(f"✅ CSV written: {csv_path}")

if __name__ == "__main__":
    main()
