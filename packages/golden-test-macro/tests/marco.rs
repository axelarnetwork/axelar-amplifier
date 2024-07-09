use golden_test_macro::golden_test;
use std::io::Write;

#[golden_test]
#[test]
fn goldenfile_basic() {
    writeln!(golden_file, "Hello, world!").unwrap();
}

#[golden_test(dir = "tests/custom_dir")]
#[test]
fn goldenfile_dir() {
    writeln!(golden_file, "Hello, world!").unwrap();
}

#[golden_test(path = "custom_path.txt")]
#[test]
fn goldenfile_path() {
    writeln!(golden_file, "Hello, world!").unwrap();
}

#[golden_test(dir = "tests/custom_dir", path = "custom_path.txt")]
#[test]
fn goldenfile_dir_and_path() {
    writeln!(golden_file, "Hello, world!").unwrap();
}
