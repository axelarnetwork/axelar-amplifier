#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/event_attributes_tuple_struct.rs");
    t.compile_fail("tests/ui/event_attributes_unit_struct.rs");
}
