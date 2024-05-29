use crate::encoding::mvx::{ed25519_key, WeightedSigners};
use crate::error::ContractError;
use crate::payload::Payload;
use axelar_wasm_std::hash::Hash;
use cosmwasm_std::HexBinary;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;

pub struct Proof {
    pub signers: WeightedSigners,
    pub signatures: Vec<Option<[u8; 64]>>,
}

impl Proof {
    pub fn new(verifier_set: &VerifierSet, mut signers_with_sigs: Vec<SignerWithSig>) -> Self {
        signers_with_sigs
            .sort_by_key(|signer| ed25519_key(&signer.signer.pub_key).expect("not ed25519 key"));

        let mut signatures = Vec::new();

        let mut signatures_index = 0;
        for signer in verifier_set.signers.values() {
            let signer_with_sig = signers_with_sigs.get(signatures_index);

            if signer_with_sig.is_some() {
                let signer_with_sig = signer_with_sig.unwrap();

                // Add correct signature if signer order is the same
                if signer == &signer_with_sig.signer {
                    signatures_index += 1;

                    let signature = <[u8; 64]>::try_from(signer_with_sig.signature.as_ref())
                        .expect("couldn't convert signature to ed25519");

                    signatures.push(Some(signature));

                    continue;
                }
            }

            // Add no signature for signer
            signatures.push(None);
        }

        Proof {
            signers: WeightedSigners::from(verifier_set),
            signatures,
        }
    }
}

pub fn encode(
    verifier_set: &VerifierSet,
    signers: Vec<SignerWithSig>,
    payload_digest: &Hash,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let proof = Proof::new(verifier_set, signers);

    // TODO:
    let data = match payload {
        Payload::Messages(messages) => {
            // let messages: Vec<_> = messages
            //     .iter()
            //     .map(|msg| Message::try_from(msg).map(IAxelarAmplifierGateway::Message::from))
            //     .collect::<Result<Vec<_>, _>>()?;
            //
            // IAxelarAmplifierGateway::approveMessagesCall::new((messages, proof.into()))
            //     .abi_encode()
            //     .into()

            HexBinary::from_hex("")?
        }
        Payload::VerifierSet(new_verifier_set) => {
            // let new_verifier_set = WeightedSigners::from(new_verifier_set);
            //
            // IAxelarAmplifierGateway::rotateSignersCall::new((new_verifier_set.into(), proof.into()))
            //     .abi_encode()
            //     .into()

            HexBinary::from_hex("")?
        }
    };

    Ok(data)
}
