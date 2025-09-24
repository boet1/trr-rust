# Multi-Tool Orchestrator (`main.py`) — ATS + TCC + TDP + TEC

`main.py` orchestrates four analysis tools—**ats**, **tcc**, **tdp**, **tec**—to produce a single CSV with per-file metrics.

It will:
1. **Clean** each module’s `output_results/` directory.
2. **Run** each tool (`ats.py`, `tcc.py`, `tdp.py`, `tec.py`) with the target directory you provide.
3. **Parse** all JSON outputs produced by those tools.
4. **Write** a unified `metrics_summary.csv`.

---

## ✅ Output

**CSV:** `metrics_summary.csv` in the current working directory, with columns:
```
File,sLOC,Token,TCC,TDP,TEC(total_cpi)
```

**Example CSV row**
```
File,sLOC,Token,TCC,TDP,TEC(total_cpi)
handlers/handler_borrow_obligation_liquidity.rs,644,1984,49,28,0
```

---

## 🚀 Usage

From the repository root (where `ats/`, `tcc/`, `tdp/`, `tec/` live):

```bash
python main.py "/home/bitnami/stack/projects/trr-rust/src/"
```

---

## 🔧 How It Works (Key Details)

- **Per-module CWD:** Each tool is executed with `cwd` set to its own folder, so relative outputs land in `<module>/output_results/`.
- **Schema-aware parsing:** The orchestrator autodetects each JSON type and extracts:
  - **ATS** → `sLoc` (as **sLOC**), `total_token` (as **Token**)
  - **TCC** → `total_tcc` (as **TCC**)
  - **TDP** → `total_tdp` (as **TDP**)
  - **TEC** → `files.*.totals.total_cpi` (as **TEC(total_cpi)**)
- **Path normalization:** Absolute/relative paths from the tools are normalized internally; the CSV shows the **relative** display path after your anchor directory.

---

## 🧩 Requirements

- **Python 3.9+**
- The four tool scripts must:
  - Live in their respective folders (`ats/`, `tcc/`, `tdp/`, `tec/`).
  - Accept one CLI argument: the directory to analyze.
  - Write JSON outputs into their own `output_results/` folder.
- Tool-specific note:
  - **ATS** expects **cloc** available on `PATH` for sLOC (uses cloc’s `code` count) and uses `len(text.split())` for tokens.

---

## 📦 Installation

First, make sure you have Python 3.8+ installed.

### 1. Clone this repository

```bash
git clone https://github.com/boet1/trr-rust.git
cd trr-rust
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```


