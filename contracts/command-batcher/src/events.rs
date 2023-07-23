use cosmwasm_std::HexBinary;

pub enum Event {
    ProofUnderConstruction { proof_id: HexBinary },
}

impl From<Event> for cosmwasm_std::Event {
    fn from(other: Event) -> Self {
        match other {
            Event::ProofUnderConstruction { proof_id } => {
                cosmwasm_std::Event::new("proof_under_construction")
                    .add_attribute("proof_id", proof_id.to_hex())
            }
        }
    }
}
