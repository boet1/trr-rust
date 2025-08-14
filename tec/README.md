# CPI Scanner (Rust + Tree-sitter)

This Python script scans **Rust** source code using [tree-sitter](https://tree-sitter.github.io/tree-sitter/) to detect **Cross-Program Invocations (CPIs)**.

It processes individual files or entire folders of `.rs` files and generates:

* ✅ A **JSON summary** of CPI sites (per file and global totals).
* ✅ An **AST (`.txt`)** dump for each Rust file to aid manual inspection.

---

## ⚙️ How It Works

The script parses Rust files with **tree-sitter** and walks the AST to find **call expressions** that match CPI patterns in Solana:

### ✅ CPI kinds detected

* **`invoke`** — direct call to `solana_program::program::invoke(...)`
* **`invoke_signed`** — direct call to `solana_program::program::invoke_signed(...)`
* **`method_invoke`** — method syntax wrapper: `obj.invoke(...)`
* **`method_invoke_signed`** — method syntax wrapper: `obj.invoke_signed(...)`
* **`anchor_cpi_helper`** — any helper call with a path containing `::cpi::` (e.g., `anchor_spl::token::cpi::transfer(...)`)

### ℹ️ Why these patterns?

In Solana, **external calls** are explicit:
- **`invoke` / `invoke_signed`** trigger a CPI to another program (with `invoke_signed` passing PDA seeds).
- Anchor/SPL **helpers** under `::cpi::` wrap those calls.
- Some codebases use **method-style** wrappers that ultimately call `invoke`/`invoke_signed`.

### 📏 “Estimated CPI Sites”

To avoid inflating counts, `total_cpi` sums **only CPI call kinds**:

```
total_cpi =
    invoke
  + invoke_signed
  + method_invoke
  + method_invoke_signed
  + anchor_cpi_helper
```

---

## 📁 Output

For each `.rs` file:

* ✅ `output_results/<file>_ast.txt` — AST dump (node kinds and spans).
* ✅ `output_results/cpi_summary.json` — aggregate JSON with:
  * `files[<path>].hits[]` — list of CPI detections with line/col, kind, callee, and code line.
  * `files[<path>].totals` — per-file counts and `total_cpi`.
  * `files[<path>].ast_file` — the AST filename.
  * `global_totals` — sum across all files.

---

## 🚀 Usage

### Analyze a single file

```bash
python tec.py src/program.rs
```

### Analyze a directory (recursive)

```bash
python tec.py src/
```

---

## 🧾 Example JSON snippet

```json
{
  "files": {
    "tests/cpi_examples.rs": {
      "ast_file": "cpi_examples_ast.txt",
      "hits": [
        { "line": 14, "col": 5, "kind": "invoke", "callee": "invoke", "code": "invoke(&instruction, &accounts).unwrap();" },
        { "line": 24, "col": 5, "kind": "invoke_signed", "callee": "invoke_signed", "code": "invoke_signed(&instruction, &accounts, &[seeds]).unwrap();" },
        { "line": 49, "col": 13, "kind": "method_invoke", "callee": "invoke", "code": "helper.invoke(&ix, &accs).unwrap();" },
        { "line": 60, "col": 13, "kind": "method_invoke_signed", "callee": "invoke_signed", "code": "helper.invoke_signed(&ix, &accs, &[seeds_level]).unwrap();" },
        { "line": 76, "col": 5, "kind": "anchor_cpi_helper", "callee": "token::cpi::transfer", "code": "token::cpi::transfer(ctx, 123u64).unwrap();" }
      ],
      "totals": {
        "invoke": 1,
        "invoke_signed": 1,
        "method_invoke": 1,
        "method_invoke_signed": 1,
        "anchor_cpi_helper": 2,
        "total_cpi": 6
      }
    }
  },
  "global_totals": {
    "invoke": 1,
    "invoke_signed": 1,
    "method_invoke": 1,
    "method_invoke_signed": 1,
    "anchor_cpi_helper": 2,
    "total_cpi": 6
  }
}
```

---

## 📝 Notes & Limitations

* The scanner is **static**: it counts **sites** in code, not how many times a CPI runs at runtime.
* Macros that generate CPIs **without** visible `invoke*` or `::cpi::` in source may be missed (rare in Anchor).
* Works best when projects call CPIs via:
  - `solana_program::program::invoke[_signed]`
  - Anchor/SPL `::cpi::...` helpers
  - Thin wrappers exposing `.invoke()` / `.invoke_signed()`



