# CPI Scanner (Rust + Tree-sitter)

This Python script scans **Rust** source code using [tree-sitter](https://tree-sitter.github.io/tree-sitter/) to detect **Cross-Program Invocations (CPIs)**.

It processes individual files or entire folders of `.rs` files and generates:

* ✅ A **JSON summary** of CPI sites (per file and global totals).
* ✅ An **AST (`.txt`)** dump for each Rust file to aid manual inspection.

---

## ⚙️ How It Works

The script parses Rust files with **tree-sitter** and walks the AST to find **call expressions** that match CPI patterns in Solana.

### ✅ CPI kinds detected

* **`invoke`** — direct call to `solana_program::program::invoke(...)`
* **`invoke_signed`** — direct call to `solana_program::program::invoke_signed(...)`
* **`method_invoke`** — method syntax wrapper: `obj.invoke(...)`
* **`method_invoke_signed`** — method syntax wrapper: `obj.invoke_signed(...)`
* **`anchor_cpi_helper`** — any helper call with a path containing `::cpi::` (e.g., `anchor_spl::token::cpi::transfer(...)`)
* **`anchor_cpi_helper_wrapped`** — Anchor helpers **without `::cpi::` in the path**, including calls via aliases (`spl_transfer`, `sys_transfer`, etc.), validated with extra context rules.

### 🔎 Context & Closure Analysis

To reduce false positives, the script inspects **how the first argument is used**:
- If the first argument is a `CpiContext` parameter (explicitly typed in a function signature).
- If a `CpiContext` is created in the same scope or in an outer scope.
- If the first argument is a closure parameter (typed or untyped) and the closure’s surrounding scope shows `CpiContext::new(...)` or `.with_signer(...)`.
- If the argument variable was previously assigned from a `CpiContext`.

This allows the scanner to detect cases such as:
```rust
let ctx = CpiContext::new(...);
let f = |amount| {
    transfer(ctx, amount).unwrap();  // Detected as CPI
};
```

---

## 📏 CPI Counting

To avoid inflating counts, `total_cpi` sums **only recognized CPI call kinds**:

```
total_cpi =
    invoke
  + invoke_signed
  + method_invoke
  + method_invoke_signed
  + anchor_cpi_helper
  + anchor_cpi_helper_wrapped
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
        { "line": 76, "col": 5, "kind": "anchor_cpi_helper", "callee": "token::cpi::transfer", "code": "token::cpi::transfer(ctx, 123u64).unwrap();" },
        { "line": 90, "col": 5, "kind": "anchor_cpi_helper_wrapped", "callee": "transfer", "code": "transfer(ctx, 50).unwrap();" }
      ],
      "totals": {
        "invoke": 1,
        "invoke_signed": 1,
        "method_invoke": 1,
        "method_invoke_signed": 1,
        "anchor_cpi_helper": 1,
        "anchor_cpi_helper_wrapped": 1,
        "total_cpi": 6
      }
    }
  },
  "global_totals": {
    "invoke": 1,
    "invoke_signed": 1,
    "method_invoke": 1,
    "method_invoke_signed": 1,
    "anchor_cpi_helper": 1,
    "anchor_cpi_helper_wrapped": 1,
    "total_cpi": 6
  }
}
```

---

## 📝 Notes & Limitations

* The scanner is **static**: it counts **sites** in code, not how many times a CPI executes at runtime.
* Wrapped helpers without `::cpi::` are detected only if supported by:
  - Known helper names (e.g., `transfer`, `mint_to`, `burn`, etc.)
  - Context validation (argument must be `CpiContext`-like).
  - Alias resolution (`use anchor_spl::token::transfer as spl_transfer;`).
* Works best when projects follow common patterns:
  - `solana_program::program::invoke[_signed]`
  - Anchor/SPL `::cpi::...` helpers
  - Anchor helpers without `::cpi::` but passing a `CpiContext`

---
