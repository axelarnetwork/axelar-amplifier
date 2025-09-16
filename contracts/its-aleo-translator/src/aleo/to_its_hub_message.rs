use aleo_gateway_types::{ItsOutgoingInterchainTransfer, RemoteDeployInterchainToken};
use aleo_gmp_types::token_id_conversion::ItsTokenIdNewType;
use aleo_gmp_types::SafeGmpChainName;
use aleo_string_encoder::StringEncoder;
use axelar_wasm_std::nonempty;
use interchain_token_service_std::{
    DeployInterchainToken as ItsHubDeployInterchainToken, HubMessage,
    InterchainTransfer as ItsHubInterchainTransfer, Message, TokenId,
};
use router_api::ChainNameRaw;
use snarkvm_cosmwasm::prelude::Network;

use crate::aleo::Error;

/// Trait to convert a message to a HubMessage
pub trait ToItsHubMessage {
    type Error;

    fn to_hub_message(self) -> Result<HubMessage, Self::Error>;
}

impl ToItsHubMessage for RemoteDeployInterchainToken {
    type Error = Error;

    fn to_hub_message(self) -> Result<HubMessage, Self::Error> {
        let RemoteDeployInterchainToken {
            payload: deploy_interchain_token,
            destination_chain,
        } = self;

        let destination_chain = SafeGmpChainName::new(destination_chain)
            .map_err(|e| Error::InvalidChainName(e.to_string()))?;
        let token_id = TokenId::from(ItsTokenIdNewType(deploy_interchain_token.its_token_id));

        let name = nonempty::String::try_from(
            StringEncoder::from_slice(&[deploy_interchain_token.name]).decode()?,
        )?;

        let symbol = nonempty::String::try_from(
            StringEncoder::from_slice(&[deploy_interchain_token.symbol]).decode()?,
        )?;

        let decimals = deploy_interchain_token.decimals;

        let minter = {
            let minter = StringEncoder::from_slice(&deploy_interchain_token.minter).decode()?;

            let minter = minter.strip_prefix("0x").unwrap_or(&minter);

            if minter.is_empty() {
                None
            } else {
                Some(nonempty::HexBinary::try_from(hex::decode(minter)?)?)
            }
        };

        let deploy_interchain_token_its_hub = ItsHubDeployInterchainToken {
            token_id,
            name,
            symbol,
            decimals,
            minter,
        };

        Ok(HubMessage::SendToHub {
            destination_chain: ChainNameRaw::try_from(destination_chain)?,
            message: Message::DeployInterchainToken(deploy_interchain_token_its_hub),
        })
    }
}

impl<N: Network> ToItsHubMessage for ItsOutgoingInterchainTransfer<N> {
    type Error = Error;

    fn to_hub_message(self) -> Result<HubMessage, Self::Error> {
        let ItsOutgoingInterchainTransfer {
            inner_message: outgoing_interchain_transfer,
            destination_chain,
        } = self;

        let destination_chain = SafeGmpChainName::new(destination_chain)
            .map_err(|e| Error::InvalidChainName(e.to_string()))?;

        let token_id = TokenId::from(ItsTokenIdNewType(outgoing_interchain_transfer.its_token_id));

        let source_address =
            StringEncoder::encode_string(&outgoing_interchain_transfer.source_address.to_string())?
                .decode()?
                .into_bytes()
                .try_into()?;

        let destination_address = {
            let destination_address =
                StringEncoder::from_slice(&outgoing_interchain_transfer.destination_address)
                    .decode()?;

            let destination_address = destination_address
                .strip_prefix("0x")
                .unwrap_or(&destination_address);

            nonempty::HexBinary::try_from(hex::decode(destination_address)?)?
        };

        let amount =
            cosmwasm_std::Uint256::from_u128(outgoing_interchain_transfer.amount).try_into()?;

        let interchain_transfer = ItsHubInterchainTransfer {
            token_id,
            source_address,
            destination_address,
            amount,
            data: None,
        };

        Ok(HubMessage::SendToHub {
            destination_chain: ChainNameRaw::try_from(destination_chain)?,
            message: Message::InterchainTransfer(interchain_transfer),
        })
    }
}
