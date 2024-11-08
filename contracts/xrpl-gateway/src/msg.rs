use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Uint256;
use interchain_token_service::TokenId;
use router_api::{ChainName, CrossChainId, Message};
use msgs_derive::EnsurePermissions;

use xrpl_types::msg::{XRPLMessage, XRPLUserMessageWithPayload};
use xrpl_types::types::{XRPLAccountId, XRPLCurrency, XRPLRemoteInterchainTokenInfo, XRPLToken, XRPLTokenOrXRP, xrpl_account_id_string};

#[cw_serde]
pub struct InstantiateMsg {
    /// Address of the verifier contract on axelar associated with the source chain. E.g., the voting verifier contract.
    pub verifier_address: String,
    /// Address of the router contract on axelar.
    pub router_address: String,
    /// Address of the ITS Hub contract on axelar.
    pub its_hub_address: String,
    /// Chain name of the axelar chain.
    pub axelar_chain_name: ChainName,
    /// Chain name of the XRPL chain.
    pub xrpl_chain_name: ChainName,
    /// Address of the Axelar Gateway multisig account on XRPL.
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub xrpl_multisig_address: XRPLAccountId,
}

#[cw_serde]
pub struct DeployInterchainTokenParams {
    pub name: nonempty::String,
    pub symbol: nonempty::String,
    pub decimals: u8,
    pub initial_supply: Uint256,
    pub minter: Option<nonempty::HexBinary>,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    // TODO
    #[permission(Admin)]
    RegisterLocalInterchainToken {
        xrpl_token: XRPLToken,
    },

    // TODO
    #[permission(Admin)]
    RegisterRemoteInterchainToken {
        token_id: TokenId,
        xrpl_currency: XRPLCurrency,
        canonical_decimals: u8,
    },

    // TODO
    #[permission(Admin)]
    DeployXrpToSidechain {
        sidechain_name: ChainName,
        deployment_params: nonempty::HexBinary,
    },

    // TODO
    #[permission(Admin)]
    DeployInterchainToken {
        xrpl_token: XRPLTokenOrXRP,
        destination_chain: ChainName,
        token_params: DeployInterchainTokenParams,
    },

    /// Before messages that are unknown to the system can be routed, they need to be verified.
    /// Use this call to trigger verification for any of the given messages that is still unverified.
    #[permission(Any)]
    VerifyMessages(Vec<XRPLMessage>),

    /// Forward the given messages to the next step of the routing layer.
    /// NOTE: In XRPL, this is only used to route outgoing messages, therefore they are already verified.
    /// NOTE: Should be named RouteOutgoingMessages, but we keep the name for compatibility with the router.
    #[permission(Any)]
    RouteMessages(Vec<Message>),

    /// Forward the given messages to the next step of the routing layer.
    /// They are reported by the relayer and need verification.
    #[permission(Any)]
    RouteIncomingMessages(Vec<XRPLUserMessageWithPayload>),
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // messages that can be relayed to the chain corresponding to this gateway
    #[returns(Vec<Message>)]
    OutgoingMessages(Vec<CrossChainId>),

    #[returns(XRPLRemoteInterchainTokenInfo)]
    TokenInfo(TokenId),
}
