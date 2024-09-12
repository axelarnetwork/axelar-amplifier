// because each test file is a module, the compiler complains about unused imports if one of the files doesn't use them.
// This circumvents that issue.
#![allow(dead_code)]

#[allow(unused_imports)]
pub use execute::*;
pub use instantiate::*;
#[allow(unused_imports)]
pub use messages::*;
#[allow(unused_imports)]
pub use query::*;

mod execute;
mod instantiate;
mod messages;
pub mod params;
mod query;
