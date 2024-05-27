pub mod abi;

use cosmwasm_schema::cw_serde;

#[cw_serde]
#[derive(Copy)]
pub enum Encoder {
    Abi,
    Bcs,
}

#[cfg(test)]
mod test {
    use router_api::CrossChainId;

    use crate::payload::PayloadId;
    use crate::test::test_data;

    #[test]
    fn test_payload_id() {
        let messages = test_data::messages();
        let mut message_ids: Vec<CrossChainId> =
            messages.into_iter().map(|msg| msg.cc_id).collect();

        let res: PayloadId = (&message_ids).into();

        message_ids.reverse();
        let res2: PayloadId = (&message_ids).into();

        assert_eq!(res, res2);
    }
}
