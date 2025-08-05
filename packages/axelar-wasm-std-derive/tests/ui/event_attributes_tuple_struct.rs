use axelar_wasm_std_derive::EventAttributes;

#[derive(EventAttributes)]
struct TupleStruct(u32, String);

fn main() {}
