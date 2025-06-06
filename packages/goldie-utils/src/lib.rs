extern crate std;

use std::env;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[doc(hidden)]
pub fn __source_file(file: &str) -> PathBuf {
    goldie::cargo_workspace_dir(env!("CARGO_MANIFEST_DIR")).join(file)
}

#[doc(hidden)]
pub fn __assert_matches_golden_file(
    actual: impl AsRef<str>,
    source_file: impl AsRef<Path>,
    function_path: impl AsRef<str>,
) {
    if let Err(err) = goldie::Goldie::new(source_file, function_path).assert(actual) {
        ::std::panic!("{}", err);
    }
}

#[doc(hidden)]
pub fn __assert_matches_golden_file_json(
    actual: impl Serialize,
    source_file: impl AsRef<Path>,
    function_path: impl AsRef<str>,
) {
    if let Err(err) = goldie::Goldie::new(source_file, function_path).assert_json(actual) {
        ::std::panic!("{}", err);
    }
}

#[macro_export]
macro_rules! assert_matches_golden_file {
    ($actual:expr) => {{
        const fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            ::std::any::type_name::<T>()
        }

        // because f() will be defined inside the parent function, we can strip away the suffix to get the parent function name
        let mut function_path = type_name_of(f).strip_suffix("::f").unwrap_or("");
        while let Some(rest) = function_path.strip_suffix("::{{closure}}") {
            function_path = rest;
        }

        let source_file = $crate::__source_file(file!());
        $crate::__assert_matches_golden_file($actual, source_file, function_path);
    }};
}

#[macro_export]
macro_rules! assert_matches_golden_file_json {
    ($actual:expr) => {{
        const fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            ::std::any::type_name::<T>()
        }

        // because f() will be defined inside the parent function, we can strip away the suffix to get the parent function name
        let mut function_path = type_name_of(f).strip_suffix("::f").unwrap_or("");
        while let Some(rest) = function_path.strip_suffix("::{{closure}}") {
            function_path = rest;
        }

        let source_file = $crate::__source_file(file!());
        $crate::__assert_matches_golden_file_json($actual, source_file, function_path);
    }};
}
