use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::str::FromStr;

use aleo_gateway_types::{
    FromRemoteDeployInterchainToken, IncomingInterchainTransfer, Message, Proof, WeightedSigner,
    WeightedSigners,
};
use aleo_string_encoder::StringEncoder;
use cosmwasm_std::Uint128;
use snarkvm_cosmwasm::prelude::{
    Address, ComputeKey, FromBytes, Group, Network, Plaintext, ProgramID, Scalar, Signature,
    Zero as _,
};

use crate::error::Error;
use crate::token_id_conversion::ItsTokenIdNewType;
use crate::SafeGmpChainName;

/// This trait provides a way to convert Rust structs to structs that
/// can be converted to Plaintext for the Aleo network.
pub trait AxelarToLeo<N: Network> {
    type LeoType: for<'a> TryFrom<&'a Plaintext<N>>;
    type Error;

    fn to_leo(&self) -> Result<Self::LeoType, Self::Error>;
}

impl<N: Network> AxelarToLeo<N> for router_api::Message {
    type LeoType = Message<N>;
    type Error = Error;

    fn to_leo(&self) -> Result<Self::LeoType, Self::Error> {
        const ALEO_ITS_CONTRACT_ADDRESS: &str =
            "aleo1ymrcwun5g9z0un8dqgdln7l3q77asqr98p7wh03dwgk4yfltpqgq9efvfz";

        let source_chain = SafeGmpChainName::try_from(&self.cc_id.source_chain)?.aleo_chain_name();
        let message_id = StringEncoder::encode_string(&self.cc_id.message_id)?.to_array()?;
        let source_address = StringEncoder::encode_string(&self.source_address)?.to_array()?;

        // TODO: THIS LOGIC NEEDS TO BE REFACTORED
        // 1. Axelar should accept the program names are addresses
        // 2. When they accept it we should keep only the conversations from ProgramID to Address
        let contract_address = match self.destination_address.as_str() {
            ALEO_ITS_CONTRACT_ADDRESS => Address::from_str(ALEO_ITS_CONTRACT_ADDRESS)?,
            str => {
                if let Ok(address) = Address::<N>::from_str(str) {
                    address
                } else {
                    // If the address is not a valid Aleo address, assume it's a ProgramID
                    // and convert it to an Address.
                    ProgramID::<N>::from_str(str)?.to_address()?
                }
            }
        };

        // The payload hash is a 32 byte array, which is a 256 bit hash.
        // (for messages from Aleo this will happen in the relayer)
        // The group values of Aleo are ~256bits, so in aleo we will only use bhp256(keccak256) hashes.
        // The result of bhp256 is a group element, which comes from Aleo.
        // We will store it in cosmos 256 bits variables just for convenience.
        let reverse_hash: Vec<u8> = self.payload_hash.iter().map(|b| b.reverse_bits()).collect();
        let keccak_bits: Vec<bool> = bytes_to_bits(&reverse_hash);

        let payload_hash = <N>::hash_to_group_bhp256(&keccak_bits)?;

        Ok(Message {
            source_chain,
            message_id,
            source_address,
            contract_address,
            payload_hash,
        })
    }
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect()
}

impl<N: Network> AxelarToLeo<N> for multisig::verifier_set::VerifierSet {
    type LeoType = WeightedSigners<N>;
    type Error = Error;

    fn to_leo(&self) -> Result<Self::LeoType, Self::Error> {
        let signers: Vec<WeightedSigner<N>> = self
            .signers
            .values()
            .map(AxelarToLeo::to_leo)
            .collect::<Result<_, _>>()?;

        let mut iter = signers.into_iter().chain(std::iter::repeat(WeightedSigner {
            addr: Address::zero(),
            weight: 0u64.into(),
        }));

        // Safe to unwrap because we ensure that there are enough signers
        let row1: [WeightedSigner<N>; 14] = std::array::from_fn(|_| iter.next().unwrap());
        let row2: [WeightedSigner<N>; 14] = std::array::from_fn(|_| iter.next().unwrap());

        Ok(Self::LeoType {
            signers: [row1, row2],
            quorum: self.threshold.into(),
            nonce: self.created_at,
        })
    }
}

impl<N: Network> AxelarToLeo<N> for multisig::msg::Signer {
    type LeoType = WeightedSigner<N>;
    type Error = Error;

    fn to_leo(&self) -> Result<Self::LeoType, Self::Error> {
        let pub_key = match &self.pub_key {
            multisig::key::PublicKey::AleoSchnorr(key) => key.as_slice(),
            _ => panic!("Unsupported public key type"), // TODO: remove panic
        };

        Ok(Self::LeoType {
            addr: Address::from_bytes_le(pub_key)?,
            weight: self.weight.into(),
        })
    }
}

pub const GROUP_SIZE: usize = 14;
pub const GROUPS: usize = 2;

type Array2D<T> = [[T; GROUP_SIZE]; GROUPS];

pub struct AxelarProof<N: Network> {
    weighted_signers: WeightedSigners<N>,
    signature: Array2D<Box<Signature<N>>>,
}

impl<N: Network> From<AxelarProof<N>> for Proof<N> {
    fn from(axelar_proof: AxelarProof<N>) -> Self {
        Proof {
            weighted_signers: axelar_proof.weighted_signers,
            signatures: axelar_proof.signature,
        }
    }
}

impl<N: Network> AxelarProof<N> {
    pub fn new(
        weighted_signers: WeightedSigners<N>,
        signer_with_signature: Vec<multisig::msg::SignerWithSig>,
    ) -> Self {
        let signer_with_signature_len = signer_with_signature.len();
        let mut address_signature: HashMap<Address<N>, Box<Signature<N>>> = signer_with_signature
            .into_iter()
            .filter_map(|signer_with_signature| {
                let (addr, sig) = match (
                    signer_with_signature.signer.pub_key,
                    signer_with_signature.signature,
                ) {
                    (
                        multisig::key::PublicKey::AleoSchnorr(key),
                        multisig::key::Signature::AleoSchnorr(sig),
                    ) => {
                        let key = Address::<N>::from_bytes_le(&key).ok();
                        let sig = Signature::<N>::from_bytes_le(&sig).ok();
                        (key?, Box::new(sig?))
                    }
                    _ => return None,
                };

                Some((addr, sig))
            })
            .collect();

        assert!(address_signature.len() == signer_with_signature_len);

        let mut signature: Array2D<MaybeUninit<Box<Signature<N>>>> =
            unsafe { MaybeUninit::uninit().assume_init() };

        for (group_idx, signer_group) in weighted_signers.signers.iter().enumerate() {
            for (signer_idx, weighted_signer) in signer_group.iter().enumerate() {
                if let Some(sig) = address_signature.remove(&weighted_signer.addr) {
                    signature[group_idx][signer_idx].write(sig);
                } else {
                    signature[group_idx][signer_idx].write(Box::new(Signature::from((
                        Scalar::<N>::zero(),
                        Scalar::<N>::zero(),
                        ComputeKey::try_from((Group::<N>::zero(), Group::<N>::zero())).unwrap(),
                    ))));
                }
            }
        }

        let signature = unsafe {
            std::mem::transmute::<
                [[MaybeUninit<Box<Signature<N>>>; 14]; 2],
                [[std::boxed::Box<snarkvm_cosmwasm::prelude::Signature<N>>; 14]; 2],
            >(signature)
        };

        AxelarProof {
            weighted_signers,
            signature,
        }
    }
}

// ITS types
impl<N: Network> AxelarToLeo<N> for interchain_token_service_std::InterchainTransfer {
    type LeoType = IncomingInterchainTransfer<N>;
    type Error = Error;

    fn to_leo(&self) -> Result<Self::LeoType, Self::Error> {
        let its_token_id = ItsTokenIdNewType::from(self.token_id);

        let source_address =
            StringEncoder::encode_bytes(self.source_address.as_slice())?.to_array()?;

        let destination_address =
            Address::from_str(std::str::from_utf8(&self.destination_address)?)?;

        let amount = Uint128::try_from(*self.amount)?.u128();

        Ok(IncomingInterchainTransfer {
            its_token_id: *its_token_id,
            source_address,
            destination_address,
            amount,
        })
    }
}

impl<N: Network> AxelarToLeo<N> for interchain_token_service_std::DeployInterchainToken {
    type LeoType = FromRemoteDeployInterchainToken<N>;
    type Error = Error;

    fn to_leo(&self) -> Result<Self::LeoType, Self::Error> {
        let its_token_id = ItsTokenIdNewType::from(self.token_id);

        let name: [u128; 2] = StringEncoder::encode_string(&self.name)?.to_array()?;

        let symbol: [u128; 2] = StringEncoder::encode_string(&self.symbol)?.to_array()?;

        let minter = match &self.minter {
            Some(hex) => Address::from_str(std::str::from_utf8(&hex)?)?,
            None => Address::zero(),
        };

        Ok(FromRemoteDeployInterchainToken {
            its_token_id: *its_token_id,
            name: name[0],
            symbol: symbol[0],
            decimals: self.decimals,
            minter,
        })
    }
}
