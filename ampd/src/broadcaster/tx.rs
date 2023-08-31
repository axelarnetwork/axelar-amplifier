use core::fmt::Debug;
use std::future::Future;

use cosmrs::tendermint::chain::Id;
use cosmrs::{
    proto::cosmos::tx::v1beta1::TxRaw,
    tx::{BodyBuilder, Fee, SignDoc, SignerInfo},
    Any, Coin,
};
use derive_builder::Builder;
use error_stack::{Context, Result, ResultExt};
use report::ResultCompatExt;
use thiserror::Error;

use crate::types::PublicKey;

const DUMMY_CHAIN_ID: &str = "dummy_chain_id";
const DUMMY_ACC_NUMBER: u64 = 0;

#[derive(Error, Debug)]
pub enum Error {
    #[error("tx signing failed")]
    Sign,
    #[error("tx marshaling failed")]
    Marshaling,
}

#[derive(Builder)]
pub struct Tx<M>
where
    M: IntoIterator<Item = Any>,
{
    msgs: M,
    pub_key: PublicKey,
    acc_sequence: u64,
    fee: Fee,
}

impl<M> TxBuilder<M>
where
    M: IntoIterator<Item = Any> + Clone,
{
    pub fn zero_fee(&mut self) -> &mut Self {
        self.fee(Fee::from_amount_and_gas(
            Coin {
                denom: "".parse().unwrap(),
                amount: 0,
            },
            0u64,
        ))
    }
}

impl<M> Tx<M>
where
    M: IntoIterator<Item = Any>,
{
    pub async fn sign_with<F, Fut, Err>(
        self,
        chain_id: &Id,
        acc_number: u64,
        sign: F,
    ) -> Result<TxRaw, Error>
    where
        F: Fn(Vec<u8>) -> Fut,
        Fut: Future<Output = Result<Vec<u8>, Err>>,
        Err: Context,
    {
        let body = BodyBuilder::new().msgs(self.msgs).finish();
        let auth_info =
            SignerInfo::single_direct(Some(self.pub_key), self.acc_sequence).auth_info(self.fee);
        let sign_doc = SignDoc::new(&body, &auth_info, chain_id, acc_number)
            .change_context(Error::Marshaling)?;

        let signature = sign(
            sign_doc
                .clone()
                .into_bytes()
                .change_context(Error::Marshaling)?,
        )
        .await
        .change_context(Error::Sign)?;

        Ok(TxRaw {
            body_bytes: sign_doc.body_bytes,
            auth_info_bytes: sign_doc.auth_info_bytes,
            signatures: vec![signature],
        })
    }

    pub async fn with_dummy_sig(self) -> Result<TxRaw, Error> {
        self.sign_with(
            &DUMMY_CHAIN_ID
                .parse()
                .expect("the dummy chain id must be valid"),
            DUMMY_ACC_NUMBER,
            |_| async { Result::<_, Error>::Ok(vec![0; 64]) },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use cosmos_sdk_proto::Any;
    use cosmrs::{
        bank::MsgSend,
        bip32::secp256k1::elliptic_curve::rand_core::OsRng,
        crypto::secp256k1::SigningKey,
        proto::cosmos::tx::v1beta1::TxRaw,
        tendermint::chain::Id,
        tx::{BodyBuilder, Fee, Msg, SignDoc, SignerInfo},
        AccountId, Coin,
    };
    use error_stack::Result;
    use k256::ecdsa;
    use k256::sha2::{Digest, Sha256};
    use tokio::test;

    use crate::types::PublicKey;

    use super::{Error, TxBuilder, DUMMY_CHAIN_ID};

    #[test]
    async fn sign_with_should_produce_the_correct_tx() {
        let priv_key = ecdsa::SigningKey::random(&mut OsRng);
        let priv_key_bytes = priv_key.to_bytes();
        let pub_key: PublicKey = priv_key.verifying_key().into();
        let acc_number = 100;
        let acc_sequence = 1000;
        let chain_id: Id = DUMMY_CHAIN_ID.parse().unwrap();
        let msgs = vec![dummy_msg(), dummy_msg(), dummy_msg()];

        let actual_tx = TxBuilder::default()
            .msgs(msgs.clone())
            .zero_fee()
            .pub_key(pub_key)
            .acc_sequence(acc_sequence)
            .build()
            .unwrap()
            .sign_with(&chain_id, acc_number, |sign_doc| async move {
                let mut hasher = Sha256::new();
                hasher.update(sign_doc);
                let hash = hasher.finalize();

                let priv_key = ecdsa::SigningKey::from_bytes(&priv_key_bytes).unwrap();
                let (signature, _) = priv_key.sign_prehash_recoverable(&hash.to_vec()).unwrap();

                Result::<_, Error>::Ok(signature.to_vec())
            })
            .await
            .unwrap();

        let body = BodyBuilder::new().msgs(msgs).finish();
        let auth_info = SignerInfo::single_direct(Some(pub_key), acc_sequence).auth_info(
            Fee::from_amount_and_gas(
                Coin {
                    denom: "".parse().unwrap(),
                    amount: 0,
                },
                0u64,
            ),
        );
        let sign_doc = SignDoc::new(&body, &auth_info, &chain_id, acc_number).unwrap();
        let expected_tx = sign_doc
            .sign(&SigningKey::from_slice(priv_key_bytes.as_slice()).unwrap())
            .unwrap();

        assert_eq!(actual_tx, expected_tx.into());
    }

    #[test]
    async fn with_dummy_sig_should_produce_the_correct_tx() {
        let pub_key: PublicKey = ecdsa::SigningKey::random(&mut OsRng).verifying_key().into();
        let acc_sequence = 1000;
        let msgs = vec![dummy_msg(), dummy_msg(), dummy_msg()];

        let actual_tx = TxBuilder::default()
            .msgs(msgs.clone())
            .zero_fee()
            .pub_key(pub_key)
            .acc_sequence(acc_sequence)
            .build()
            .unwrap()
            .with_dummy_sig()
            .await
            .unwrap();

        let body = BodyBuilder::new().msgs(msgs).finish();
        let auth_info = SignerInfo::single_direct(Some(pub_key), acc_sequence).auth_info(
            Fee::from_amount_and_gas(
                Coin {
                    denom: "".parse().unwrap(),
                    amount: 0,
                },
                0u64,
            ),
        );
        let expected_tx = TxRaw {
            body_bytes: body.into_bytes().unwrap(),
            auth_info_bytes: auth_info.into_bytes().unwrap(),
            signatures: vec![vec![0; 64]],
        };

        assert_eq!(actual_tx, expected_tx);
    }

    fn dummy_msg() -> Any {
        MsgSend {
            from_address: AccountId::new("", &[1, 2, 3]).unwrap(),
            to_address: AccountId::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }
}
