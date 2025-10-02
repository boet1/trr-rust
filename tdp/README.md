# Rust Total Decision Points (TDP) Analyzer

This Python script analyzes **Total Decision Points (TDP)** of Rust code using the [tree-sitter](https://tree-sitter.github.io/tree-sitter/) parsing library.

It processes individual Rust files or entire folders containing `.rs` files and generates:

* ✅ A **JSON summary** of Total Decision Points (TDP) per file and per function.
* ✅ An **AST (Abstract Syntax Tree)** `.txt` file for each Rust source file.

---

## ⚙️ How It Works

This script calculates **Total Decision Points (TDP)** for each function in your Rust codebase.

### What are Decision Points?

Decision Points represent control structures that can alter the flow of execution.  
A higher TDP indicates more complex logic and potentially harder-to-maintain code.

### ✅ **What Counts as Decision Points (TDP Calculation):**

The script counts **one point per occurrence** of the following Rust syntax nodes:

* `if_expression` (+1) 
* `while_expression`
* `for_expression`
* `loop_expression`
* `match_arm`
* `try_expression` (`?` operator)
* Panic-like macros: `panic!`, `assert!`, `assert_eq!`, `assert_ne!`,  
  `debug_assert!`, `debug_assert_eq!`, `debug_assert_ne!`,  
  `unreachable!`, `todo!`, `unimplemented!`

#### 💡 Why These Nodes?

These structures introduce **decision branches** in the code:

* **Conditionals (if/else, match)**: introduce branching logic.
* **Loops (for, while, loop)**: create iterative decision structures.
* **Try expressions**: may propagate errors and alter control flow.
* **Panic-like macros**: abort execution, similar to `require`, `assert`, `revert` in Solidity.

---

## 📁 Output

For each `.rs` file:

* ✅ A file `output_results/filename_ast.txt` contains the full AST breakdown.
* ✅ The JSON file `output_results/tdp_summary.json` shows:

  * List of functions with TDP count
  * Total TDP per file
  * AST filename

---

## 🚀 Usage Example

### ✅ Analyzing a single Rust file:

```bash
python tdp.py src/processor.rs
```

### ✅ Analyzing directories:

```bash
python tdp.py src/
```

### ✅ Example of the final JSON output:

```json
{
  "src/processor.rs": {
    "functions": [
      {"name": "process_data", "tdp": 7}
    ],
    "total_tdp": 7,
    "ast_file": "processor_ast.txt"
  }
}
```

