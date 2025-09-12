//! This module defines the types used in the multisig prover, for Aleo.

use std::fmt::Debug;

use aleo_gateway_types::constants::{MAX_SIGNATURES, SIGNATURE_CHUNKS, SINGATURES_PER_CHUNK};
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use serde::{Deserialize, Serialize};
use snarkvm_cosmwasm::prelude::{Address, FromBytes as _, Network};

use crate::aleo_struct::AxelarToLeo;
use crate::error::Error;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(bound = "Address<N>: for<'a> Deserialize<'a>")]
pub struct WeightedSigners<N>
where
    N: Network,
{
    signers: Vec<WeightedSigner<N>>,
    quorum: u128,
    nonce: u64,
}

impl<N: Network> WeightedSigners<N> {
    pub fn new(verifier_set: &VerifierSet) -> Result<Self, Error> {
        let signers: Vec<WeightedSigner<N>> = verifier_set
            .signers
            .values()
            .map(|s| WeightedSigner::<N>::new(s))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            signers,
            quorum: verifier_set.threshold.into(),
            nonce: verifier_set.created_at,
        })
    }
}

impl<N: Network> AxelarToLeo<N> for WeightedSigners<N> {
    type LeoType = aleo_gateway_types::WeightedSigners<N>;
    type Error = Error;

    fn to_leo(&self) -> Result<Self::LeoType, Self::Error> {
        let signers: Vec<aleo_gateway_types::WeightedSigner<N>> = self
            .signers
            .iter()
            .map(AxelarToLeo::to_leo)
            .collect::<Result<_, _>>()?;

        let mut iter = signers
            .into_iter()
            .chain(std::iter::repeat(aleo_gateway_types::WeightedSigner {
                addr: Address::zero(),
                weight: 0u64.into(),
            }))
            .take(MAX_SIGNATURES);

        let signers: [[aleo_gateway_types::WeightedSigner<N>; SINGATURES_PER_CHUNK];
            SIGNATURE_CHUNKS] =
            std::array::from_fn(|_| std::array::from_fn(|_| iter.next().unwrap()));

        Ok(aleo_gateway_types::WeightedSigners {
            signers,
            quorum: self.quorum,
            nonce: self.nonce,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(bound = "Address<N>: for<'a> Deserialize<'a>")]
pub struct WeightedSigner<N>
where
    N: Network,
{
    pub addr: Address<N>,
    pub weight: u128,
}

impl<N: Network> WeightedSigner<N> {
    pub fn new(signer: &Signer) -> Result<Self, Error> {
        let pub_key = match &signer.pub_key {
            multisig::key::PublicKey::AleoSchnorr(key) => key.as_slice(),
            _ => return Err(Error::InvalidPublicKey),
        };

        Ok(Self {
            addr: Address::from_bytes_le(pub_key)?,
            weight: signer.weight.into(),
        })
    }
}

impl<N: Network> AxelarToLeo<N> for WeightedSigner<N> {
    type LeoType = aleo_gateway_types::WeightedSigner<N>;
    type Error = Error;

    fn to_leo(&self) -> Result<Self::LeoType, Self::Error> {
        Ok(aleo_gateway_types::WeightedSigner {
            addr: self.addr,
            weight: self.weight,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(bound = "Address<N>: for<'a> Deserialize<'a>")]
pub struct Proof<N>
where
    N: Network,
{
    pub weighted_signers: WeightedSigners<N>,
    pub signatures: Vec<multisig::key::Signature>,
}

impl<N: Network> Proof<N> {
    pub fn new(
        verifier_set: &VerifierSet,
        signer_with_signature: Vec<multisig::msg::SignerWithSig>,
    ) -> Result<Self, Error> {
        let weighted_signers = WeightedSigners::new(verifier_set)?;

        let mut address_signature = signer_with_signature
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
                        let key = Address::<N>::from_bytes_le(&key).ok()?;
                        (key, multisig::key::Signature::AleoSchnorr(sig))
                    }
                    _ => return None, // Unsupported key/signature type
                };
                Some((addr, sig))
            })
            .collect::<std::collections::HashMap<_, _>>();

        let mut signatures = Vec::with_capacity(weighted_signers.signers.len());
        for signer in &weighted_signers.signers {
            if let Some(sig) = address_signature.remove(&signer.addr) {
                signatures.push(sig);
            }
        }

        Ok(Self {
            weighted_signers,
            signatures,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(bound = "Address<N>: for<'a> Deserialize<'a>")]
pub struct ExecuteData<N>
where
    N: Network,
{
    pub proof: Proof<N>,
    /// Note: Here messages are provided as a flat vector.
    /// The relayer is responsible to fill this with empty messages, to fill a [[Messages; 24]; 2] array,
    /// before providing to Aleo gateway.
    pub messages: Vec<aleo_gateway_types::Message<N>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "Address<N>: for<'a> Deserialize<'a>")]
pub struct ExecuteSignersRotation<N>
where
    N: Network,
{
    pub proof: Proof<N>,
    pub new_verifier_set: aleo_gateway_types::WeightedSigners<N>,
}
