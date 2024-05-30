use crate::encoding::mvx::{ed25519_key, Message, WeightedSigners};
use crate::error::ContractError;
use crate::payload::Payload;
use cosmwasm_std::HexBinary;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use multiversx_sc_codec::top_encode_to_vec_u8;

pub struct Proof {
    pub signers: WeightedSigners,
    pub signatures: Vec<Option<[u8; 64]>>,
}

impl Proof {
    pub fn new(verifier_set: &VerifierSet, signers_with_sigs: Vec<SignerWithSig>) -> Self {
        let signers = WeightedSigners::from(verifier_set);

        let mut signers_with_sigs = signers_with_sigs
            .into_iter()
            .map(|signer| {
                let key = ed25519_key(&signer.signer.pub_key).expect("not ed25519 key");

                (key, signer.signature)
            })
            .collect::<Vec<_>>();

        signers_with_sigs.sort_by_key(|signer| signer.0);

        let mut signatures = Vec::new();

        let mut signatures_index = 0;
        for signer in signers.signers.iter() {
            let signer_with_sig = signers_with_sigs.get(signatures_index);

            if signer_with_sig.is_some() {
                let signer_with_sig = signer_with_sig.unwrap();

                // Add correct signature if signer order is the same
                if signer.signer == signer_with_sig.0 {
                    signatures_index += 1;

                    let signature = <[u8; 64]>::try_from(signer_with_sig.1.as_ref())
                        .expect("couldn't convert signature to ed25519");

                    signatures.push(Some(signature));

                    continue;
                }
            }

            // Add no signature for signer
            signatures.push(None);
        }

        Proof {
            signers,
            signatures,
        }
    }

    pub fn encode(self) -> Result<Vec<u8>, ContractError> {
        let signers = self.signers.dep_encode()?;

        Ok(top_encode_to_vec_u8(&(signers, self.signatures))
            .expect("couldn't serialize proof as mvx"))
    }
}

pub fn encode(
    verifier_set: &VerifierSet,
    signers: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let proof = Proof::new(verifier_set, signers);

    let data = match payload {
        Payload::Messages(messages) => {
            let messages: Vec<_> = messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<_, _>>()?;

            let messages =
                top_encode_to_vec_u8(&messages).expect("couldn't serialize messages as mvx");
            let proof = proof.encode()?;

            let messages: HexBinary = messages.into();
            let proof: HexBinary = proof.into();

            // TODO: Test if this is right
            let result = format!("approveMessages@{}@{}", messages, proof);

            HexBinary::from(result.as_bytes())
        }
        Payload::VerifierSet(new_verifier_set) => {
            let new_verifier_set = WeightedSigners::from(new_verifier_set).top_encode()?;
            let proof = proof.encode()?;

            let new_verifier_set: HexBinary = new_verifier_set.into();
            let proof: HexBinary = proof.into();

            // TODO: Test if this is right
            let result = format!("rotateSigners@{}@{}", new_verifier_set, proof);

            HexBinary::from(result.as_bytes())
        }
    };

    Ok(data)
}
