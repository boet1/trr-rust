// tests/cpi_examples.rs
// This file contains CPI examples for static scanning tests.
// It does not need to compile; it only exists to exercise the scanner.

// ----- Imports typically seen in real programs (not required to compile) -----
use solana_program::program::{invoke, invoke_signed}; // identifier form
use anchor_spl::{token, associated_token};            // helper modules with ::cpi::

// New imports for helpers WITHOUT ::cpi::
use anchor_lang::system_program::transfer;
use anchor_lang::system_program::transfer as sys_transfer;
use anchor_spl::token_interface::transfer_checked;
use anchor_spl::associated_token::create_idempotent;

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

#[allow(dead_code)]
struct CpiContext<T>(T);
#[allow(dead_code)]
impl<T> CpiContext<T> {
    fn new(_program: (), _accounts: T) -> Self { CpiContext(_accounts) }
    fn with_signer(self, _seeds: &[&[u8]]) -> Self { self }
}

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

// ============================================================================
// NEW SECTION: Anchor helpers WITHOUT ::cpi::
// ============================================================================

#[allow(dead_code)]
fn example_system_program_transfer_identifier() {
    // Scanner should tag: kind = "anchor_cpi_helper"
    let ctx = CpiContext::new((), SystemTransfer { from: (), to: () });
    transfer(ctx, 100u64).unwrap();
}

#[allow(dead_code)]
fn example_system_program_transfer_alias_signed() {
    // Scanner should tag: kind = "anchor_cpi_helper_signed"
    let ctx = CpiContext::new((), SystemTransfer { from: (), to: () })
        .with_signer(&[&[b"seed", &[1]]]);
    sys_transfer(ctx, 200u64).unwrap();
}

#[allow(dead_code)]
fn example_token_interface_transfer_checked_identifier(amount: u64, ctx: CpiContext<Transfer>) {

    transfer_checked(ctx, 777u64, 6u8).unwrap();
}

#[allow(dead_code)]
fn example_associated_token_create_idempotent_identifier() {
    // Scanner should tag: kind = "anchor_cpi_helper"
    
    create_idempotent(CpiContext::new((), AssociatedCreateIdempotent {
        payer: (), associated_token: (), authority: (), mint: (),
        system_program: (), token_program: ()
    })).unwrap();
}

fn demo(ctx: CpiContext<Transfer>, amount: u64) {
    token::transfer(ctx, amount).unwrap();   
}

// Stand-in structs for the new examples
#[allow(dead_code)]
struct SystemTransfer { from: (), to: () }

#[allow(dead_code)]
struct TokenTransferChecked { from: (), mint: (), to: (), authority: () }

#[allow(dead_code)]
struct AssociatedCreateIdempotent {
    payer: (), associated_token: (), authority: (), mint: (), system_program: (), token_program: ()
}


// =====================================================
// CLOSURE TEST CASES FOR CPI DETECTION
// =====================================================

use anchor_lang::system_program::transfer;
use anchor_spl::token::transfer as spl_transfer;
use anchor_spl::token::transfer_checked;

// Fake context struct for tests
struct SystemTransfer { from: (), to: () }
struct TokenTransfer { from: (), to: (), authority: () }

// Stand-in for CpiContext
#[allow(dead_code)]
struct CpiContext<T>(T);
impl<T> CpiContext<T> {
    fn new(_p: (), _a: T) -> Self { CpiContext(_a) }
    fn with_signer(self, _s: &[&[u8]]) -> Self { self }
}

// =====================================================
// 1) Confirmed CPI: closure param typed as CpiContext
// =====================================================

#[allow(dead_code)]
fn closure_with_typed_ctx() {
    let f = |ctx: CpiContext<SystemTransfer>| {
        transfer(ctx, 123).unwrap();
    };
}

// =====================================================
// 2) Confirmed CPI: builds CpiContext inside closure
// =====================================================

#[allow(dead_code)]
fn closure_builds_ctx() {
    let f = || {
        let ctx = CpiContext::new((), SystemTransfer { from: (), to: () })
            .with_signer(&[&[b"seed", &[1]]]);
        transfer(ctx, 456).unwrap();
    };
}

// =====================================================
// 3) High-confidence CPI: ctx built outside, closure param untyped
// =====================================================

#[allow(dead_code)]
fn closure_uses_outer_ctx() {
    let ctx = CpiContext::new((), SystemTransfer { from: (), to: () })
        .with_signer(&[&[b"seed", &[2]]]);

    let f = |amount| {
        transfer(ctx, amount).unwrap();
    };
}

// =====================================================
// 4) High-confidence CPI: closure takes ctx untyped, outer scope has CpiContext
// =====================================================

#[allow(dead_code)]
fn closure_param_untyped() {
    let ctx = CpiContext::new((), TokenTransfer { from: (), to: (), authority: () });
    let f = |ctx, amt| {
        spl_transfer(ctx, amt).unwrap();
    };
}

// =====================================================
// 5) Confirmed CPI: first arg is function param typed as CpiContext
// =====================================================

#[allow(dead_code)]
fn fn_param_with_closure(ctx: CpiContext<TokenTransfer>) {
    let f = |amt| {
        transfer_checked(ctx, amt, 9).unwrap();
    };
}
