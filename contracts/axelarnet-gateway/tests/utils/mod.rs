// because each test file is a module, the compiler complains about unused imports if one of the files doesn't use them.
// This circumvents that issue.
#![allow(dead_code)]

#[cfg_attr(test, allow(unused_imports))]
pub use deps::*;
#[allow(unused_imports)]
pub use execute::*;
pub use instantiate::*;

mod deps;
mod execute;
mod instantiate;
pub mod messages;
pub mod params;
