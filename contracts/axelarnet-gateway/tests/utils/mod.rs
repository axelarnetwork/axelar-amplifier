// because each test file is a module, the compiler complains about unused imports if one of the files doesn't use them.
// This circumvents that issue.
#![allow(dead_code)]

#[allow(unused_imports)]
pub use execute::*;
pub use instantiate::*;

mod execute;
mod instantiate;
pub mod messages;
pub mod params;
