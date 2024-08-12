use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Uint128;
use itertools::Itertools;

use crate::key::Signature;
use crate::msg::{Signer, SignerWithSig};
use crate::types::MultisigState;
use crate::verifier_set::VerifierSet;

#[cw_serde]
pub struct Multisig {
    pub state: MultisigState,
    pub verifier_set: VerifierSet,
    pub signatures: HashMap<String, Signature>,
}

impl Multisig {
    /// Returns the minimum amount of signers with signatures to satisfy the quorum, sorted by weight
    pub fn optimize_signatures(&self) -> Vec<SignerWithSig> {
        self.signatures
            .iter()
            .sorted_by(|(addr_a, _), (addr_b, _)| {
                self.signer(addr_b).weight.cmp(&self.signer(addr_a).weight)
            })
            .scan(Uint128::zero(), |acc, (addr, signature)| {
                let signer = self.signer(addr);

                if *acc < self.verifier_set.threshold {
                    *acc = acc.saturating_add(signer.weight);
                    Some(signer.with_sig(signature.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    fn signer(&self, address: &str) -> &Signer {
        self.verifier_set
            .signers
            .get(address)
            .expect("signer not found in verifier set")
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::{Addr, HexBinary, Uint128};

    use crate::key::{PublicKey, Signature};
    use crate::msg::Signer;
    use crate::multisig::Multisig;
    use crate::types::MultisigState;
    use crate::verifier_set::VerifierSet;

    #[test]
    fn optimize_signatures() {
        let signers = vec![
            signer("signer0", 1),
            signer("signer1", 3),
            signer("signer2", 5),
            signer("signer3", 7),
            signer("signer4", 6),
            signer("signer5", 4),
            signer("signer6", 2),
        ];

        let sig = Signature::Ecdsa(HexBinary::from([0; 64]).try_into().unwrap());

        // signer 0, 2, 3, 6 submitted signatures
        let sigs = vec![
            ("signer0".to_string(), sig.clone()),
            ("signer2".to_string(), sig.clone()),
            ("signer3".to_string(), sig.clone()),
            ("signer6".to_string(), sig.clone()),
        ];

        let threshold = Uint128::from(13u64);

        // optimized signers are signer 3 (weight 7), signer 2 (weight 5), signer 6 (weight 2)
        let expected_optimized_signers = vec![
            signers[3].with_sig(sig.clone()),
            signers[2].with_sig(sig.clone()),
            signers[6].with_sig(sig.clone()),
        ];

        let verifier_set = VerifierSet {
            signers: signers
                .iter()
                .map(|s| (s.address.to_string(), s.clone()))
                .collect(),
            threshold,
            created_at: 1,
        };

        let multisig = Multisig {
            state: MultisigState::Completed { completed_at: 1 },
            verifier_set,
            signatures: sigs.into_iter().collect(),
        };

        assert_eq!(multisig.optimize_signatures(), expected_optimized_signers);
    }

    fn signer(address: &str, weight: u64) -> Signer {
        Signer {
            address: Addr::unchecked(address),
            weight: weight.into(),
            pub_key: PublicKey::Ecdsa(HexBinary::from([0; 32])),
        }
    }
}
