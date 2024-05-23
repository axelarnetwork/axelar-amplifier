pub mod abi;

use cosmwasm_schema::cw_serde;

use axelar_wasm_std::operators::Operators;
use multisig::verifier_set::VerifierSet;

#[cw_serde]
#[derive(Copy)]
pub enum Encoder {
    Abi,
    Bcs,
}

pub fn make_operators(worker_set: VerifierSet, encoder: Encoder) -> Operators {
    match encoder {
        Encoder::Abi => abi::make_operators(worker_set),
        Encoder::Bcs => todo!(),
    }
}

#[cfg(test)]
mod test {
    use router_api::CrossChainId;

    use crate::test::test_data;
    use crate::types::BatchId;

    #[test]
    fn test_batch_id() {
        let messages = test_data::messages();
        let mut message_ids: Vec<CrossChainId> =
            messages.into_iter().map(|msg| msg.cc_id).collect();

        let res = BatchId::new(&message_ids, None);

        message_ids.reverse();
        let res2 = BatchId::new(&message_ids, None);

        assert_eq!(res, res2);
    }
}
