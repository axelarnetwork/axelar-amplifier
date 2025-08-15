use std::str::FromStr as _;

use aleo_gmp_types::SafeGmpChainName;
use aleo_string_encoder::StringEncoder;
use cosmwasm_std::Uint128;
use interchain_token_service_std::InterchainTransfer as InterchainTransferItsHub;
use router_api::ChainNameRaw;
use snarkvm_cosmwasm::prelude::{Address, Network, Plaintext, Value};

use crate::aleo::token_id_conversion::ItsTokenIdNewType;
use crate::aleo::try_from_impl::{
    FromRemoteDeployInterchainToken, IncomingInterchainTransfer, ItsIncomingInterchainTransfer,
    ItsMessageDeployInterchainToken,
};
use crate::aleo::Error;

/// Trait to convert a message to an Aleo Value
pub trait ToAleoValue<N: Network> {
    type Error;

    fn to_aleo_value(self, source_chain: ChainNameRaw) -> Result<Value<N>, Self::Error>;
}

impl<N: Network> ToAleoValue<N> for interchain_token_service_std::DeployInterchainToken {
    type Error = Error;

    fn to_aleo_value(self, source_chain: ChainNameRaw) -> Result<Value<N>, Self::Error> {
        let its_token_id = ItsTokenIdNewType::from(self.token_id);

        let name: [u128; 2] = StringEncoder::encode_string(&self.name)?.to_array()?;

        let symbol: [u128; 2] = StringEncoder::encode_string(&self.symbol)?.to_array()?;

        let minter = match self.minter {
            Some(hex) => Address::from_str(std::str::from_utf8(&hex)?)?,
            None => Address::zero(),
        };

        let source_chain = SafeGmpChainName::try_from(&source_chain)?;

        let deploy_interchain_token = FromRemoteDeployInterchainToken {
            its_token_id: *its_token_id,
            name: name[0],
            symbol: symbol[0],
            decimals: self.decimals,
            minter,
        };

        let message = ItsMessageDeployInterchainToken {
            inner_message: deploy_interchain_token,
            source_chain: source_chain.aleo_chain_name(),
        };

        let aleo_plaintext = Plaintext::try_from(&message)?;

        Ok(Value::Plaintext(aleo_plaintext))
    }
}

impl<N: Network> ToAleoValue<N> for InterchainTransferItsHub {
    type Error = Error;

    fn to_aleo_value(self, source_chain: ChainNameRaw) -> Result<Value<N>, Self::Error> {
        let its_token_id = ItsTokenIdNewType::from(self.token_id);

        let source_address =
            StringEncoder::encode_bytes(self.source_address.as_slice())?.to_array()?;

        let destination_address =
            Address::from_str(std::str::from_utf8(&self.destination_address)?)?;

        let amount = Uint128::try_from(*self.amount)?.u128();

        let source_chain = SafeGmpChainName::try_from(&source_chain)?;

        let interchain_transfer = IncomingInterchainTransfer {
            its_token_id: *its_token_id,
            source_address,
            destination_address,
            amount,
        };

        let message = ItsIncomingInterchainTransfer {
            inner_message: interchain_transfer,
            source_chain: source_chain.aleo_chain_name(),
        };

        let aleo_plaintext = Plaintext::try_from(&message)?;

        Ok(Value::Plaintext(aleo_plaintext))
    }
}
