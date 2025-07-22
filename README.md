# Rust Cyclomatic Complexity Analyzer

This Python script analyzes **Cyclomatic Complexity (CC)** of Rust code using the [tree-sitter](https://tree-sitter.github.io/tree-sitter/) parsing library.

It processes individual Rust files or entire folders containing `.rs` files and generates:

* ✅ A **JSON summary** of Total Cyclomatic Complexity (TCC) per file and per function.
* ✅ An **AST (Abstract Syntax Tree)** `.txt` file for each Rust source file.

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

---

## ⚙️ How It Works

This script calculates **Cyclomatic Complexity (CC)** for each function  in your Rust codebase.

### What is Cyclomatic Complexity?

Cyclomatic Complexity measures the number of independent paths through a program. A higher number suggests more complex, harder-to-maintain code.

### ✅ **What Counts as Decision Points (TCC Calculation):**

The script counts **one point per occurrence** of the following Rust syntax nodes:

* `if_expression`
* `for_expression`
* `while_expression`
* `loop_expression`
* `match_arm`
* `try_expression`
* `closure_expression`
* Logical operators: `&&` and `||`

#### 💡 Why These Nodes?

These structures introduce **decision branches** in the code:

* **Conditionals (if, match)**: branch logic.
* **Loops (for, while, loop)**: introduce cycles.
* **Closures**: are counted as independent logical units.
* **Logical operators (&&, ||)**: create short-circuiting branches.
* **Try expressions**: may cause non-linear control flow.

Each function’s TCC is calculated as:

```
TCC = 1 (default function path) + total decision points inside the function
```

---

## 📁 Output

For each `.rs` file:

* ✅ A file `output_results/filename_ast.txt` contains the full AST breakdown.
* ✅ The JSON file `output_results/tcc_summary.json` shows:

  * List of functions with TCC
  * Total TCC per file
  * AST filename

---

## 🚀 Usage Example

### ✅ Analyzing a single Rust file:

```bash
python tcc.py src/processor.rs
```

### ✅ Analyzing directories:

```bash
python tcc.py src/
```

### ✅ Example of the final JSON output:

```json
{
  "src/processor.rs": {
    "functions": [
      {"name": "process_data", "tcc": 7},
      {"name": "function_anon_1", "tcc": 3}
    ],
    "total_tcc": 10,
    "ast_file": "processor_ast.txt"
  }
}
```

## 💡 Notes

* Only files with `.rs` extension are processed.
* AST files can be used for further static analysis.
