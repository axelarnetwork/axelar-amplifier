use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, HexBinary};
use interchain_token_service::{TokenId, TokenManagerType};
use router_api::{ChainName, ChainNameRaw, CrossChainId, Message};
use msgs_derive::EnsurePermissions;

use xrpl_types::msg::{XRPLMessage, XRPLUserMessageWithPayload};
use xrpl_types::types::{xrpl_account_id_string, xrpl_currency_string, XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken, XRPLTokenOrXrp};

#[cw_serde]
pub struct InstantiateMsg {
    /// Address that can execute all messages that either have unrestricted or admin permission level, such as Updateverifier set.
    /// Should be set to a trusted address that can react to unexpected interruptions to the contract's operation.
    pub admin_address: String,
    /// Address that can call all messages of unrestricted, admin and governance permission level, such as UpdateSigningThreshold.
    /// This address can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
    /// On mainnet, it should match the address of the Cosmos governance module.
    pub governance_address: String,
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
pub struct DeployInterchainToken {
    /// The name of the token
    pub name: nonempty::String,
    /// The symbol of the token
    pub symbol: nonempty::String,
    /// The number of decimal places the token supports
    pub decimals: u8,
    /// An additional minter of the token (optional). ITS on the external chain is always a minter.
    pub minter: Option<nonempty::HexBinary>,
}

#[cw_serde]
pub struct DeployTokenManager {
    /// The type of token manager to deploy
    pub token_manager_type: TokenManagerType,
    /// The parameters to be provided to the token manager contract
    pub params: nonempty::HexBinary,
    /// The number of decimal places the token supports
    pub decimals: u8,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Register an XRPL token.
    #[permission(Elevated)]
    RegisterLocalToken {
        xrpl_token: XRPLToken,
    },

    /// Register a remote token on the XRPL chain,
    /// defining its XRPL currency.
    #[permission(Elevated)]
    RegisterRemoteToken {
        token_id: TokenId,
        #[serde(with = "xrpl_currency_string")]
        #[schemars(with = "String")]
        xrpl_currency: XRPLCurrency,
    },

    /// Register a remote token that is deployed on another chain.
    #[permission(Elevated)]
    RegisterTokenInstance {
        token_id: TokenId,
        chain: ChainNameRaw,
        decimals: u8,
    },

    /// Deploy a token manager on some destination chain.
    #[permission(Elevated)]
    DeployTokenManager {
        xrpl_token: XRPLTokenOrXrp,
        destination_chain: ChainNameRaw,
        deploy_token_manager: DeployTokenManager,
    },

    /// Deploy an interchain token on some destination chain.
    #[permission(Elevated)]
    DeployInterchainToken {
        xrpl_token: XRPLTokenOrXrp,
        destination_chain: ChainNameRaw,
        deploy_token: DeployInterchainToken,
    },

    /// Before messages that are unknown to the system can be routed, they need to be verified.
    /// Use this call to trigger verification for any of the given messages that is still unverified.
    #[permission(Any)]
    VerifyMessages(Vec<XRPLMessage>),

    /// Forward the given outgoing messages (coming to XRPL) to the next step of the routing layer.
    /// NOTE: In XRPL, this is only used to route outgoing messages, therefore they are already verified.
    /// NOTE: Should be named RouteOutgoingMessages, but we keep the name for compatibility with the router.
    #[permission(Specific(router))]
    RouteMessages(Vec<Message>),

    /// Forward the given incoming messages (coming from XRPL) to the next step of the routing layer.
    /// They are reported by the relayer and need verification.
    #[permission(Any)]
    RouteIncomingMessages(Vec<XRPLUserMessageWithPayload>),

    /// Offload dust accrued to the multisig prover.
    #[permission(Elevated)]
    OffloadDust {
        multisig_prover: Addr,
        token_id: TokenId,
    },
}

#[cw_serde]
pub struct MessageWithPayload {
    pub message: Message,
    pub payload: HexBinary,
}

#[cw_serde]
pub struct InterchainTransfer {
    pub message_with_payload: Option<MessageWithPayload>,
    pub token_id: TokenId,
    pub dust: XRPLPaymentAmount,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // messages that can be relayed to the chain corresponding to this gateway
    #[returns(Vec<Message>)]
    OutgoingMessages(Vec<CrossChainId>),

    #[returns(XRPLToken)]
    XrplToken(TokenId),

    #[returns(u8)]
    TokenInstanceDecimals {
        chain_name: ChainNameRaw,
        token_id: TokenId,
    },

    #[returns(InterchainTransfer)]
    InterchainTransfer {
        #[serde(flatten)]
        message_with_payload: XRPLUserMessageWithPayload,
    },
}
