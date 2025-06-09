#![feature(rustc_private)]

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use rustc_lint::LintStore;
use rustc_tools::with_lints;

mod unwrap_call;

/*

READ HERE FOR INFO

should use -p or --bin?

run the cargo_integration one with:
    cargo +nightly-2024-07-25 run -p andrew-linter-test
- this will run on the entire amplifier repo.
- this one fails on trait bound errors.

run the other one with:
    cargo +nightly-2024-07-25 run -p andrew-linter-test [file]
- test dummy file is ampd/src/foo.rs.
- this one works, but only on single files without dependencies, and with a main function.

*/

fn main() {
    // let cargo_args = std::env::args().skip(2).collect::<Vec<_>>();
    // rustc_tools::cargo_integration(&cargo_args, |args| {
    //     with_lints(args, vec![], |store: &mut LintStore| {
    //         store.register_late_pass(|_| Box::new(unwrap_call::UnwrapCall));
    //     }).expect("with_lints failed");
    // }).expect("cargo_integration failed");

    // let args = std::env::args().collect::<Vec<_>>();
    // with_lints(&args, vec![], |store: &mut LintStore| {
    //     store.register_late_pass(|_| Box::new(unwrap_call::UnwrapCall));
    // }).expect("with_lints failed");
}
