// tests/cpi_examples.rs
// This file contains CPI examples for static scanning tests.
// It does not need to compile; it only exists to exercise the scanner.

// ----- Imports typically seen in real programs (not required to compile) -----
use solana_program::program::{invoke, invoke_signed}; // identifier form
use anchor_spl::{token, associated_token};            // helper modules with ::cpi::

#[allow(dead_code)]
fn example_invoke_identifier_form() {
    // Identifier call: invoke(...)
    // Scanner should tag: kind = "invoke"
    let instruction = /* ... */ ();
    let accounts = /* ... */ [/* ... */];
    invoke(&instruction, &accounts).unwrap();
}

#[allow(dead_code)]
fn example_invoke_signed_identifier_form() {
    // Identifier call: invoke_signed(...)
    // Scanner should tag: kind = "invoke_signed"
    let instruction = /* ... */ ();
    let accounts = /* ... */ [/* ... */];
    let seeds: &[&[u8]] = &[b"seed_prefix", &[42]];
    invoke_signed(&instruction, &accounts, &[seeds]).unwrap();
}

#[allow(dead_code)]
fn example_invoke_scoped_form() {
    // Scoped identifier: solana_program::program::invoke(...)
    // Scanner should tag: kind = "invoke"
    let ix = /* ... */ ();
    let accs = /* ... */ [/* ... */];
    solana_program::program::invoke(&ix, &accs).unwrap();
}

#[allow(dead_code)]
fn example_invoke_signed_scoped_form() {
    // Scoped identifier: solana_program::program::invoke_signed(...)
    // Scanner should tag: kind = "invoke_signed"
    let ix = /* ... */ ();
    let accs = /* ... */ [/* ... */];
    let signer_seeds: &[&[u8]] = &[b"pda_seed", &[7]];
    solana_program::program::invoke_signed(&ix, &accs, &[signer_seeds]).unwrap();
}

// ----- Method-style wrappers (field_expression -> .invoke / .invoke_signed) -----

struct MyCpiHelper;

impl MyCpiHelper {
    #[allow(dead_code)]
    fn new() -> Self { Self }

    #[allow(dead_code)]
    fn invoke(&self, _ix: &(), _accs: &[()]) -> Result<(), ()> { Ok(()) }

    #[allow(dead_code)]
    fn invoke_signed(&self, _ix: &(), _accs: &[()], _seeds: &[&[&[u8]]]) -> Result<(), ()> { Ok(()) }
}

#[allow(dead_code)]
fn example_method_invoke() {
    // Method call: helper.invoke(...)
    // Scanner should tag: kind = "method_invoke"
    let helper = MyCpiHelper::new();
    let ix = /* ... */ ();
    let accs = /* ... */ [/* ... */];
    helper.invoke(&ix, &accs).unwrap();
}

#[allow(dead_code)]
fn example_method_invoke_signed() {
    // Method call: helper.invoke_signed(...)
    // Scanner should tag: kind = "method_invoke_signed"
    let helper = MyCpiHelper::new();
    let ix = /* ... */ ();
    let accs = /* ... */ [/* ... */];
    let seeds_level: &[&[u8]] = &[b"seedA", &[1]];
    helper.invoke_signed(&ix, &accs, &[seeds_level]).unwrap();
}

// ----- Anchor/SPL helper calls with ::cpi:: (anchor_cpi_helper) -----

#[allow(dead_code)]
fn example_anchor_spl_token_transfer() {
    // Helper: anchor_spl::token::cpi::transfer(...)
    // Scanner should tag: kind = "anchor_cpi_helper"
    // CpiContext hint (not a CPI by itself):
    let ctx = CpiContext::new(/* token_program */ todo!(), token::Transfer {
        from: todo!(),
        to: todo!(),
        authority: todo!(),
    });
    token::cpi::transfer(ctx, 123u64).unwrap();
}

#[allow(dead_code)]
fn example_anchor_spl_ata_create() {
    // Helper: anchor_spl::associated_token::cpi::create(...)
    // Scanner should tag: kind = "anchor_cpi_helper"
    // Another CpiContext hint line:
    let ctx = CpiContext::new(/* associated_token_program */ todo!(), associated_token::Create {
        payer: todo!(),
        associated_token: todo!(),
        authority: todo!(),
        mint: todo!(),
        system_program: todo!(),
        token_program: todo!(),
        rent: todo!(),
    });
    associated_token::cpi::create(ctx).unwrap();
}

// ----- Minimal stand-ins so CpiContext::<...> appears in source -----

// Fake CpiContext to produce "CpiContext<..." text for the scanner hint.
// In real Anchor code, you'd use: use anchor_lang::prelude::*; and CpiContext from Anchor.
#[allow(dead_code)]
struct CpiContext<T>(T);
#[allow(dead_code)]
impl<T> CpiContext<T> {
    fn new(_program: (), _accounts: T) -> Self { CpiContext(_accounts) }
}

// Token and ATA account structs shapes just for the source text (not real)
#[allow(dead_code)]
mod token {
    pub struct Transfer {
        pub from: (),
        pub to: (),
        pub authority: (),
    }
    pub mod cpi {
        use super::Transfer;
        #[allow(dead_code)]
        pub fn transfer<T>(_ctx: crate::CpiContext<Transfer>, _amount: u64) -> Result<(), ()> { Ok(()) }
    }
}

#[allow(dead_code)]
mod associated_token {
    pub struct Create {
        pub payer: (),
        pub associated_token: (),
        pub authority: (),
        pub mint: (),
        pub system_program: (),
        pub token_program: (),
        pub rent: (),
    }
    pub mod cpi {
        use super::Create;
        #[allow(dead_code)]
        pub fn create<T>(_ctx: crate::CpiContext<Create>) -> Result<(), ()> { Ok(()) }
    }
}
