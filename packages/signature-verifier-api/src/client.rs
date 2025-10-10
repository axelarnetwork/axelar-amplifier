use cosmwasm_std::{CosmosMsg, Empty, HexBinary, Uint64};

use crate::msg::ExecuteMsg;
pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, Empty>,
}

impl<'a> From<client::ContractClient<'a, ExecuteMsg, Empty>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, Empty>) -> Self {
        Client { client }
    }
}

impl Client<'_> {
    pub fn verify_signature(
        &self,
        signature: HexBinary,
        message: HexBinary,
        public_key: HexBinary,
        signer_address: String,
        session_id: Uint64,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::VerifySignature {
            signature,
            message,
            public_key,
            signer_address,
            session_id,
        })
    }
}
