# Rust Tokens & sLOC Analyzer (ATS)

This Python script computes **Tokens** and **source Lines of Code (sLOC)** .

It can analyze a single `.rs` file or recursively walk a directory of Rust sources and produces a compact JSON report.

---

## ⚙️ What It Measures

- **sLoc** — calculated using **cloc**'s `code` count (source lines only, excluding blanks and comments).
- **total_token** — calculated as a lightweight size proxy: `len(text.split())` on each file's raw UTF-8 text.

---

## 📁 Output

Results are written to `ats/output_results/` as a JSON file:

```json
{
  "files": {
    "/absolute/or/relative/path/to/lib.rs": {
      "total_token": 1984,
      "sLoc": 644
    }
  }
}
```

---

## 🚀 Usage

Analyze a **single file**:
```bash
python ats.py src/processor.rs
```

Analyze a **directory** (recursive over `*.rs`):
```bash
python ats.py src/
```

---

## ✅ Requirements

- **cloc** installed and available on `PATH`.
  - Typical call used by the script is equivalent to:
    ```bash
    cloc --json --by-file --include-lang=Rust <TARGET>
    ```

---
