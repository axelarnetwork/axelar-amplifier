use starknet_core::types::{Event, Felt};
use thiserror::Error;

/// An error, representing failure to convert/parse a starknet event
/// to a SignersRotated event.
#[derive(Error, Debug)]
pub enum SignersRotatedErrors {
    /// Error returned when a required signers hash is missing from a
    /// transaction.
    #[error("missing signers hash for transaction")]
    MissingSignersHash,

    /// Error returned when payload data cannot be parsed correctly.
    #[error("failed to parse payload data, error: {0}")]
    FailedToParsePayloadData(String),

    /// Error returned when the payload data is missing.
    #[error("missing payload data for transaction")]
    MissingPayloadData,

    /// Error returned when the epoch number in a transaction is invalid or
    /// unexpected.
    #[error("incorrect epoch for transaction")]
    IncorrectEpoch,

    /// Error returned when the first key doesn't correspod to the
    /// SignersRotated event.
    #[error("not a SignersRotated event")]
    InvalidEvent,

    /// Error returned when the threshold in a transaction is invalid or
    /// unexpected.
    #[error("incorrect threshold for transaction")]
    IncorrectThreshold,

    /// Error returned when the nonce in a transaction is missing.
    #[error("missing nonce for transaction")]
    MissingNonce,

    /// Error returned when the keys in a transaction are missing.
    #[error("missing keys for transaction")]
    MissingKeys,
}

/// Represents a weighted signer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signer {
    /// The address of the signer
    pub signer: String,
    /// The weight (voting power) of this signer
    pub weight: u128,
}

/// Represents a set of signers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedSigners {
    pub signers: Vec<Signer>,
    pub threshold: u128,
    pub nonce: [u8; 32],
}

/// Represents a Starknet SignersRotated event
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignersRotatedEvent {
    /// The address of the sender
    pub from_address: String,
    /// The epoch number when this rotation occurred
    pub epoch: u64,
    /// The hash of the new signers
    pub signers_hash: [u8; 32],
    /// The new set of weighted signers with their voting power
    pub signers: WeightedSigners,
}

impl TryFrom<starknet_core::types::Event> for SignersRotatedEvent {
    type Error = SignersRotatedErrors;

    /// Attempts to convert a Starknet event to a SignersRotated event
    ///
    /// # Arguments
    ///
    /// * `event` - The Starknet event to convert
    ///
    /// # Returns
    ///
    /// * `Ok(SignersRotated)` - Successfully converted event containing:
    ///   * `epoch` - The epoch number when rotation occurred
    ///   * `signers_hash` - Hash of the new signers (32 bytes)
    ///   * `signers` - New set of weighted signers with:
    ///     * List of signers with their addresses and weights
    ///     * Threshold for required voting power
    ///     * Nonce value (32 bytes)
    ///
    /// # Errors
    ///
    /// Returns a `SignersRotatedErrors` if:
    /// * Event data or keys are empty
    /// * Failed to parse epoch number
    /// * Missing or invalid signers hash
    /// * Failed to parse signers array length
    /// * Failed to parse signer addresses or weights
    /// * Missing or invalid threshold
    /// * Missing or invalid nonce
    fn try_from(event: Event) -> Result<Self, Self::Error> {
        if event.data.is_empty() {
            return Err(SignersRotatedErrors::MissingPayloadData);
        }
        if event.keys.is_empty() {
            return Err(SignersRotatedErrors::MissingKeys);
        }

        let from_address = event.from_address.to_hex_string();

        // it starts at 2 because 0 is the selector and 1 is the from_address
        let epoch_index = 2;
        // INFO: there might be better way to convert to u64
        let epoch = event
            .keys
            .get(epoch_index)
            .ok_or(SignersRotatedErrors::IncorrectEpoch)?
            .to_string()
            .parse::<u64>()
            .map_err(|_| SignersRotatedErrors::IncorrectEpoch)?;

        // Construct signers hash
        let mut signers_hash = [0_u8; 32];
        let lsb = event
            .keys
            .get(epoch_index + 1)
            .map(Felt::to_bytes_be)
            .ok_or(SignersRotatedErrors::MissingSignersHash)?;
        let msb = event
            .keys
            .get(epoch_index + 2)
            .map(Felt::to_bytes_be)
            .ok_or(SignersRotatedErrors::MissingSignersHash)?;
        signers_hash[..16].copy_from_slice(&msb[16..]);
        signers_hash[16..].copy_from_slice(&lsb[16..]);

        // Parse signers array from event data
        let mut buff_signers = vec![];

        let signers_index = 0;
        let signers_len = event.data[signers_index]
            .to_string()
            .parse::<usize>()
            .map_err(|_| {
                SignersRotatedErrors::FailedToParsePayloadData(
                    "failed to parse signers length".to_string(),
                )
            })?;
        let signers_end_index = signers_index.saturating_add(signers_len.saturating_mul(2));

        // Parse signers and weights
        for i in 0..signers_len {
            let signer_index = signers_index
                .saturating_add(1)
                .saturating_add(i.saturating_mul(2));
            let weight_index = signer_index.saturating_add(1);

            // Get signer address as bytes
            let signer = event.data[signer_index].to_hex_string();

            // Parse weight
            let weight = event.data[weight_index]
                .to_string()
                .parse::<u128>()
                .map_err(|_| {
                    SignersRotatedErrors::FailedToParsePayloadData(
                        "failed to parse signer weight".to_string(),
                    )
                })?;

            buff_signers.push(Signer { signer, weight });
        }

        // Parse threshold
        let threshold = event
            .data
            .get(signers_end_index)
            .ok_or(SignersRotatedErrors::IncorrectThreshold)?
            .to_string()
            .parse::<u128>()
            .map_err(|_| SignersRotatedErrors::IncorrectThreshold)?;

        // Parse nonce
        let mut nonce = [0_u8; 32];
        let lsb = event
            .data
            .get(event.data.len().saturating_sub(2))
            .map(Felt::to_bytes_be)
            .ok_or(SignersRotatedErrors::MissingNonce)?;
        let msb = event
            .data
            .get(event.data.len().saturating_sub(1))
            .map(Felt::to_bytes_be)
            .ok_or(SignersRotatedErrors::MissingNonce)?;
        nonce[16..].copy_from_slice(&lsb[16..]);
        nonce[..16].copy_from_slice(&msb[16..]);

        Ok(SignersRotatedEvent {
            from_address,
            epoch,
            signers_hash,
            signers: WeightedSigners {
                signers: buff_signers,
                threshold,
                nonce,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    // use futures::stream::{FuturesUnordered, StreamExt};
    use starknet_core::types::{EmittedEvent, Felt};

    use super::*;

    async fn get_valid_event() -> (Vec<Felt>, Vec<Felt>, Felt, Felt) {
        let keys_data: Vec<Felt> = vec![
            Felt::from_hex_unchecked(
                "0x01815547484542c49542242a23bc0a1b762af99232f38c0417050825aea8fc93",
            ),
            Felt::from_hex_unchecked(
                "0x0268929df65ee595bb8592323f981351efdc467d564effc6d2e54d2e666e43ca",
            ),
            Felt::from_hex_unchecked("0x01"),
            Felt::from_hex_unchecked("0xd4203fe143363253c89a27a26a6cb81f"),
            Felt::from_hex_unchecked("0xe23e7704d24f646e5e362c61407a69d2"),
        ];

        let event_data: Vec<Felt> = vec![
            Felt::from_hex_unchecked("0x01"),
            Felt::from_hex_unchecked("0x3ec7d572a0fe479768ac46355651f22a982b99cc"),
            Felt::from_hex_unchecked("0x01"),
            Felt::from_hex_unchecked("0x01"),
            Felt::from_hex_unchecked("0x2fe49d"),
            Felt::from_hex_unchecked("0x00"),
        ];
        (
            keys_data,
            event_data,
            // sender_address
            Felt::from_hex_unchecked(
                "0x0282b4492e08d8b6bbec8dfe7412e42e897eef9c080c5b97be1537433e583bdc",
            ),
            // tx_hash
            Felt::from_hex_unchecked(
                "0x04663231715b17dd58cd08e63d6b31d2c86b158d4730da9a1b75ca2452c9910c",
            ),
        )
    }

    /// Generate a set of data with random modifications
    async fn get_malformed_event() -> (Vec<Felt>, Vec<Felt>, Felt, Felt) {
        let (mut keys_data, mut event_data, sender_address, tx_hash) = get_valid_event().await;
        // Randomly remove an element from either vector
        match rand::random::<bool>() {
            true if !keys_data.is_empty() => {
                let random_index = rand::random::<usize>() % keys_data.len();
                keys_data.remove(random_index);
            }
            false if !event_data.is_empty() => {
                let random_index = rand::random::<usize>() % event_data.len();
                event_data.remove(random_index);
            }
            _ => {}
        }

        // Randomly corrupt data values
        if rand::random::<bool>() {
            if let Some(elem) = keys_data.first_mut() {
                *elem = Felt::from_hex_unchecked("0xdeadbeef");
            }
        }
        if rand::random::<bool>() {
            if let Some(elem) = event_data.first_mut() {
                *elem = Felt::from_hex_unchecked("0xcafebabe");
            }
        }

        (keys_data, event_data, sender_address, tx_hash)
    }

    #[tokio::test]
    async fn test_try_from_event_happy_scenario() {
        let (keys_data, event_data, sender_address, _tx_hash) = get_valid_event().await;

        assert!(SignersRotatedEvent::try_from(Event {
            from_address: sender_address,
            keys: keys_data,
            data: event_data,
        })
        .is_ok());
    }

    #[tokio::test]
    async fn test_try_from_empty_event() {
        let (_, _, sender_address, _tx_hash) = get_valid_event().await;
        let result = SignersRotatedEvent::try_from(Event {
            data: vec![],
            from_address: sender_address,
            keys: vec![],
        });

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_try_from_event_missing_data() {
        let (keys_data, _, sender_address, _tx_hash) = get_valid_event().await;
        let event = SignersRotatedEvent::try_from(Event {
            data: vec![],
            from_address: sender_address,
            keys: keys_data,
        });

        assert!(event.is_err());
        assert!(matches!(
            event,
            Err(SignersRotatedErrors::MissingPayloadData)
        ));
    }

    #[tokio::test]
    async fn test_try_from_event_missing_keys() {
        let (_, event_data, sender_address, _tx_hash) = get_valid_event().await;
        let event = SignersRotatedEvent::try_from(Event {
            data: event_data,
            from_address: sender_address,
            keys: vec![],
        });

        assert!(event.is_err());
        assert!(matches!(event, Err(SignersRotatedErrors::MissingKeys)));
    }

    #[tokio::test]
    async fn test_try_from_event_randomly_malformed_data_x1000() {
        // let mut futures = FuturesUnordered::new();

        for _ in 0..1000 {
            // futures.push(async {
                let (_, event_data, sender_address, tx_hash) = get_malformed_event().await;
                let event = EmittedEvent {
                    data: event_data,
                    from_address: sender_address,
                    keys: vec![],
                    transaction_hash: tx_hash,
                    block_hash: None,
                    block_number: None,
                };
                let result = SignersRotatedEvent::try_from(Event {
                    data: event.data,
                    from_address: event.from_address,
                    keys: event.keys,
                });
                assert!(result.is_err());
            // });
        }

        // if any conversion succeeded then it should have failed
        // while let Some(result) = futures.next().await {
            // if !result {
                // panic!("expected conversion to fail for malformed event");
            // }
        // }
    }
}
