use axelar_wasm_std::hash::Hash;
use cosmwasm_std::{Empty, HexBinary};
use error_stack::{Result, ResultExt};
use multisig::{msg::SignerWithSig, verifier_set::VerifierSet};
use multisig_prover_api::payload::Payload;

use crate::msg::{QueryMsg};
use crate::error::Error;

impl<'a> From<client::ContractClient<'a, Empty, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, Empty, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, Empty, QueryMsg>,
}

impl Client<'_> {

    pub fn payload_digest(
        &self,
        domain_separator: Hash,
        signer: VerifierSet,
        payload: Payload,
    ) -> Result<Hash, Error> {
        let msg = QueryMsg::PayloadDigest {
            domain_separator,
            signer,
            payload,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn encode_exec_data(
        &self,
        domain_separator: Hash,
        verifier_set: VerifierSet,
        signers: Vec<SignerWithSig>,
        payload: Payload,
    ) -> Result<HexBinary, Error> {
        let msg = QueryMsg::EncodeExecData {
            domain_separator,
            verifier_set,
            signers,
            payload,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn validate_address(&self, address: String) -> Result<bool, Error> {
        let msg = QueryMsg::ValidateAddress { address };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}

#[cfg(test)]
mod test {

    use cosmwasm_std::testing::{MockApi, MockQuerier};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, QuerierWrapper, SystemError, Uint64, WasmQuery,
    };

    use crate::client::Client;
    use crate::msg::QueryMsg;

    // TODO: add tests
}
