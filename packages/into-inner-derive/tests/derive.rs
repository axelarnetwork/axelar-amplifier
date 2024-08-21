use into_inner_derive::IntoInner;

#[derive(IntoInner)]
struct Test(u128);

#[test]
fn can_into_inner() {
    let expected_inner = 32;
    let actual_inner = Test(expected_inner).into_inner();
    assert_eq!(actual_inner, expected_inner);
}
