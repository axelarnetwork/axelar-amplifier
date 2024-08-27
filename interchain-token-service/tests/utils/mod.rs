// because each test file is a module, the compiler complains about unused imports if one of the files doesn't use them.
// This circumvents that issue.
#![allow(dead_code)]

pub use instantiate::*;
#[allow(unused_imports)]
pub use execute::*;
#[allow(unused_imports)]
pub use query::*;

mod execute;
mod instantiate;
pub mod params;
mod query;
