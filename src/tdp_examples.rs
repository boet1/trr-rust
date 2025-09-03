use std::io::{self, Read};
use std::num::ParseIntError;

// --- try_expression via '?' ---
fn parse_number(s: &str) -> Result<i32, ParseIntError> {
    // try_expression (?)
    let n = s.trim().parse::<i32>()?;
    Ok(n)
}

// --- if/else, while, for, loop, closure with internal decisions ---
fn control_flow_examples(mut x: i32) -> i32 {
    // if + else (should count as +2 in TDP: if + else)
    if x > 10 {
        x -= 1;
    } else {
        x += 2;
    }

    // while
    while x < 15 {
        x += 1;
    }

    // for
    for i in 0..3 {
        x += i;
    }

    // loop
    let mut k = 0;
    loop {
        if k >= 2 {
            break;
        }
        k += 1;
    }

    // closure with internal decisions (counted inside parent function)
    let decide = |y: i32| -> i32 {
        if y % 2 == 0 {
            0
        } else {
            // match with several arms
            match y {
                1 => 1,
                3 | 5 | 7 => 2,
                _ if y > 10 => 3, // match_arm with guard
                _ => 4,
            }
        }
    };

    x + decide(x)
}

// --- panic-like macros (equivalent to require/assert/revert in Solidity) ---
fn invariant_checks(a: i32, b: i32) {
    assert!(a >= 0);
    assert_eq!(a + b, b + a);
    assert_ne!(a, a - 1);
    debug_assert!(b >= 0);
    debug_assert_eq!(a + 1, (a + 1));
    debug_assert_ne!(b, b - 1);

    if a == 42 {
        panic!("42 is not allowed");
    }

    // These also should be detected
    // Uncomment one to avoid unreachable warnings if necessary
    // unreachable!();
    // todo!("not yet implemented");
}

// --- more panic-like macros for the detector ---
fn more_abortives() {
    // Uncomment one if you want fewer warnings
    unreachable!("this code path should never be reached");
    // unimplemented!("this function is not implemented yet");
}

// --- match example to check match_expression + match_arm ---
fn classify(value: Option<i32>) -> i32 {
    match value {
        Some(n) if n > 10 => 10,
        Some(0) => 0,
        Some(_) => 1,
        None => -1,
    }
}

// --- function using '?' operator with Result ---
fn io_with_try() -> io::Result<String> {
    let mut s = String::new();
    io::stdin().read_line(&mut s)?; // try_expression
    Ok(s)
}

// --- non-panic macros (should NOT be counted) ---
fn non_panic_macros() {
    println!("hello");
    eprintln!("error example");
    format!("format {}", 123);
}

fn main() -> io::Result<()> {
    // try_expression in main
    let input = io_with_try()?;
    let _parsed = parse_number(&input).ok();

    let _ = control_flow_examples(5);
    invariant_checks(1, 2);
    more_abortives();
    let _c = classify(Some(7));

    non_panic_macros();

    Ok(())
}
