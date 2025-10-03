# Rust Test Sanitizer & Reporter (AST-based)

A small Python utility that walks one or more Rust codebases, **removes test-only code**, and produces a **JSON report** of all `#[cfg(test)]` and `#[test]` attributes **before** sanitization.

---

## What it does

- **Removes entire test blocks _and_ their attributes:**
  - Any item annotated with `#[cfg(test)]` is removed **from the first attribute in the group to the end of the item**.
  - Files that contain an **inner attribute** `#![cfg(test)]` at the top level are removed entirely.
  - If attributes appear without a following item on the same attribute group, the attributes themselves are removed.
- **Generates a JSON report** with every `#[cfg(test)]` and `#[test]` occurrence (file, line, and line_text) **prior to sanitization**.
- **Preserves the directory structure** and copies non-`.rs` files as-is.

---

## How it works

- Uses the Rust grammar via **tree-sitter** to analyze the AST precisely.
- Collects consecutive **outer attributes** adjacent to an item; if any in the group is `#[cfg(test)]`, it deletes the span from the **first attribute** to the **end of the item**.
- The **reporter** is a simple regex that scans for `#[cfg(test)]` and `#[test]` before any changes are applied.

---

## Usage

```bash
python sanitize_rust_tests.py ./crate1 ./crate2 ./another_crate   -o sanitized_output   -r found_test_attributes.json
```

---

## Output

### 1) Sanitized copy
Creates a sanitized copy under your chosen output directory keeping the **same layout**, but with **test-only blocks removed**.

```
sanitized_output/
 ├─ crate1/
 │   └─ src/...
 └─ crate2/
     └─ src/...
```

### 2) JSON report
Contains all the occurrences found **before** sanitization.

**Example**
```json
[
  {
    "file": "/abs/path/src/lib.rs",
    "attribute": "cfg(test)",
    "line": 3,
    "line_text": "#[cfg(test)]"
  },
  {
    "file": "/abs/path/src/lib.rs",
    "attribute": "test",
    "line": 12,
    "line_text": "    #[test]"
  }
]
```

---
