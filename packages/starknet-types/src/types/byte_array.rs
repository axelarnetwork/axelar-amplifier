use itertools::FoldWhile::{Continue, Done};
use itertools::Itertools;
use starknet_core::types::Felt;
use starknet_core::utils::parse_cairo_short_string;
use thiserror::Error;

/// Represents Cairo's ByteArray type.
/// Implements `TryFrom<Vec<Felt>>`, which is the way to create it.
///
/// ## Example usage with the string "hello"
///
/// ```rust
/// use starknet_types::types::byte_array::ByteArray;
/// use std::str::FromStr;
/// use starknet_core::types::Felt;
/// use starknet_core::types::FromStrError;
///
/// let data: Result<Vec<Felt>, FromStrError> = vec![
///         "0x0000000000000000000000000000000000000000000000000000000000000000",
///         "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
///         "0x0000000000000000000000000000000000000000000000000000000000000005",
/// ]
/// .into_iter()
/// .map(Felt::from_str)
/// .collect();
///
/// let byte_array = ByteArray::try_from(data.unwrap());
/// assert!(byte_array.is_ok());
/// ```
///
/// For more info:
/// https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
#[derive(Debug, Default)]
pub struct ByteArray {
    /// The data byte array. Contains 31-byte chunks of the byte array.
    data: Vec<Felt>,
    /// The bytes that remain after filling the data array with full 31-byte
    /// chunks
    pending_word: Felt,
    /// The byte count of the pending_word
    pending_word_length: u8, // can't be more than 30 bytes
}

#[derive(Error, Debug)]
pub enum ByteArrayError {
    #[error("Failed to fetch element from byte array at index")]
    OutOfBound,
    #[error("Invalid byte array - {0}")]
    InvalidByteArray(String),
    #[error("Failed to convert felt - {0}")]
    ParsingFelt(String),
    #[error("Failed to convert the byte array into a string")]
    ToString,
}

impl TryFrom<Vec<Felt>> for ByteArray {
    type Error = ByteArrayError;

    fn try_from(data: Vec<Felt>) -> Result<Self, Self::Error> {
        // pending word is always the next to last element
        let pending_word_index = data.len().wrapping_sub(2);
        let last_element_index = data.len().wrapping_sub(1);

        let mut byte_array = ByteArray {
            ..Default::default()
        };

        if data.len() < 3 {
            return Err(ByteArrayError::InvalidByteArray(
                "vec should have minimum 3 elements".to_owned(),
            ));
        }

        // word count is always the first element, which is a felt (so u8 is enough)
        let word_count =
            u8::try_from(data[0]).map_err(|e| ByteArrayError::ParsingFelt(e.to_string()))?;

        // vec element count should be whatever the word count is + an offset of 3
        // the 3 stands for the minimum 3 elements:
        // - word count
        // - pending_word
        // - pendint_word_length
        let word_count_usize = usize::from(word_count.wrapping_add(3));
        if word_count_usize != data.len() {
            return Err(ByteArrayError::InvalidByteArray(
                "pre-defined count doesn't match actual 31byte element count".to_owned(),
            ));
        }

        // pending word byte count is always the last element
        let pending_word_length_felt = data
            .get(last_element_index)
            .ok_or(ByteArrayError::OutOfBound)?;
        let pending_word_length = u8::try_from(*pending_word_length_felt)
            .map_err(|e| ByteArrayError::ParsingFelt(e.to_string()))?;
        byte_array.pending_word_length = pending_word_length;

        let pending_word = data
            .get(pending_word_index)
            .ok_or(ByteArrayError::OutOfBound)?;
        byte_array.pending_word = *pending_word;

        // count bytes, excluding leading zeros
        let non_zero_pw_length = pending_word
            .to_bytes_be()
            .iter()
            .fold_while(32, |acc: u8, n| {
                if *n == 0 {
                    Continue(acc.saturating_sub(1))
                } else {
                    Done(acc)
                }
            })
            .into_inner();

        if pending_word_length != non_zero_pw_length {
            return Err(ByteArrayError::InvalidByteArray(
                "pending_word length doesn't match it's defined length".to_owned(),
            ));
        }

        if word_count > 0 {
            let byte_array_data = data
                .get(1..pending_word_index)
                .ok_or(ByteArrayError::OutOfBound)?
                .to_vec();

            byte_array.data = byte_array_data;
        }

        Ok(byte_array)
    }
}

impl ByteArray {
    /// Takes the ByteArray struct and tries to parse it as a single string
    ///
    /// ## Example usage with the string "hello"
    ///
    /// ```rust
    /// use starknet_types::types::byte_array::ByteArray;
    /// use std::str::FromStr;
    /// use starknet_core::types::Felt;
    /// use starknet_core::types::FromStrError;
    ///
    /// let data: Result<Vec<Felt>, FromStrError> = vec![
    ///         "0x0000000000000000000000000000000000000000000000000000000000000000",
    ///         "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
    ///         "0x0000000000000000000000000000000000000000000000000000000000000005",
    /// ]
    /// .into_iter()
    /// .map(Felt::from_str)
    /// .collect();
    ///
    /// let byte_array = ByteArray::try_from(data.unwrap()).unwrap();
    /// assert_eq!("hello", byte_array.try_to_string().unwrap());
    /// ```
    ///
    /// Additional documentation you can find here:
    /// https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
    pub fn try_to_string(&self) -> Result<String, ByteArrayError> {
        match self
            .data
            .iter()
            .chain(std::iter::once(&self.pending_word))
            .map(parse_cairo_short_string)
            .collect::<Result<String, _>>()
        {
            Ok(s) => Ok(s),
            Err(_) => Err(ByteArrayError::ToString),
        }
    }
}

#[cfg(test)]
mod byte_array_tests {
    use std::str::FromStr;

    use starknet_core::types::{Felt, FromStrError};

    use super::ByteArray;

    #[test]
    fn byte_array_parse_fail_wrong_pending_word_length() {
        // Example for a small string (fits in a single felt) taken from here:
        // https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
        //
        // So this is the string "hello"
        let data: Result<Vec<Felt>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000068656c6c6f",
            // Should be of length 5 bytes, but we put 6 bytes, in order to fail
            // the parsing
            "0x0000000000000000000000000000000000000000000000000000000000000020",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array = ByteArray::try_from(data.unwrap());
        assert!(byte_array.is_err());
    }

    #[test]
    fn byte_array_to_string_error() {
        // Example for a small string (fits in a single felt) taken from here:
        // https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
        //
        // So this is the string "hello"
        let data: Result<Vec<Felt>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            // Note the 01 in the beginning. This is what causes the parse
            // function to error.
            "0x01000000000000000000000000000000000000000000000000000068656c6c6f",
            // 32(0x20) bytes long pending_word
            "0x0000000000000000000000000000000000000000000000000000000000000020",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array = ByteArray::try_from(data.unwrap()).unwrap();
        assert!(byte_array.try_to_string().is_err());
    }

    #[test]
    fn byte_array_single_pending_word_only_to_string_valid() {
        // Example for a small string (fits in a single felt) taken from here:
        // https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
        //
        // So this is the string "hello"
        let data: Result<Vec<Felt>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
            "0x0000000000000000000000000000000000000000000000000000000000000005",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array = ByteArray::try_from(data.unwrap()).unwrap();
        assert_eq!("hello", byte_array.try_to_string().unwrap());
    }

    #[test]
    fn byte_array_to_long_string_valid() {
        // Example for a long string (doesn't fit in a single felt) taken from here:
        // https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
        //
        // So this is the string "Long long string, a lot more than 31 characters that
        // wouldn't even fit in two felts, so we'll have at least two felts and a
        // pending word."
        let data: Result<Vec<Felt>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000004",
            "0x00004c6f6e67206c6f6e6720737472696e672c2061206c6f74206d6f72652074",
            "0x000068616e2033312063686172616374657273207468617420776f756c646e27",
            "0x000074206576656e2066697420696e2074776f2066656c74732c20736f207765",
            "0x0000276c6c2068617665206174206c656173742074776f2066656c747320616e",
            "0x0000000000000000000000000000006420612070656e64696e6720776f72642e",
            "0x0000000000000000000000000000000000000000000000000000000000000011",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array = ByteArray::try_from(data.unwrap()).unwrap();
        assert_eq!("Long long string, a lot more than 31 characters that wouldn't even fit in two felts, so we'll have at least two felts and a pending word.", byte_array.try_to_string().unwrap());
    }

    #[test]
    fn try_from_vec_count_less_then_3() {
        let data: Result<Vec<Felt>, FromStrError> =
            vec!["0x0000000000000000000000000000000000000000000000000000000000000005"]
                .into_iter()
                .map(Felt::from_str)
                .collect();

        let byte_array_err = ByteArray::try_from(data.unwrap());
        assert!(byte_array_err.is_err());
    }

    #[test]
    fn try_from_non_u32_word_count() {
        let data: Result<Vec<Felt>, FromStrError> = vec![
            // should be 0, because the message is short
            // enough to fit in a single Felt
            "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
            "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
            "0x0000000000000000000000000000000000000000000000000000000000000005",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array_err = ByteArray::try_from(data.unwrap());
        assert!(byte_array_err.is_err());
    }
    #[test]
    fn try_from_invalid_byte_array_element_count() {
        let data: Result<Vec<Felt>, FromStrError> = vec![
            // should be 0, because the message is short
            // enough to fit in a single Felt
            "0x0000000000000000000000000000000000000000000000000000000000000005",
            "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
            "0x0000000000000000000000000000000000000000000000000000000000000005",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array_err = ByteArray::try_from(data.unwrap());
        assert!(byte_array_err.is_err());
    }

    #[test]
    fn try_from_non_u8_pending_word_length() {
        // Example for a small string (fits in a single felt) taken from here:
        // https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
        //
        // So this is the string "hello"
        let data: Result<Vec<Felt>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
            "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array = ByteArray::try_from(data.unwrap());
        assert!(byte_array.is_err());
    }

    #[test]
    fn try_from_valid_only_pending_word() {
        // Example for a small string (fits in a single felt) taken from here:
        // https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
        //
        // So this is the string "hello"
        let data: Result<Vec<Felt>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x00000000000000000000000000000000000000000000000000000068656c6c6f",
            "0x0000000000000000000000000000000000000000000000000000000000000005",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array = ByteArray::try_from(data.unwrap()).unwrap();

        assert_eq!(byte_array.data, vec![]);
        assert_eq!(
            byte_array.pending_word,
            Felt::from_str("0x00000000000000000000000000000000000000000000000000000068656c6c6f",)
                .unwrap()
        );
        assert_eq!(byte_array.pending_word_length, 5);
    }

    #[test]
    fn try_from_valid_one_big_string_split_in_multiple_data_elements() {
        // Example for a long string (doesn't fit in a single felt) taken from here:
        // https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
        //
        // So this is the string "Long long string, a lot more than 31 characters that
        // wouldn't even fit in two felts, so we'll have at least two felts and a
        // pending word."
        let data: Result<Vec<Felt>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000004",
            "0x00004c6f6e67206c6f6e6720737472696e672c2061206c6f74206d6f72652074",
            "0x000068616e2033312063686172616374657273207468617420776f756c646e27",
            "0x000074206576656e2066697420696e2074776f2066656c74732c20736f207765",
            "0x0000276c6c2068617665206174206c656173742074776f2066656c747320616e",
            "0x0000000000000000000000000000006420612070656e64696e6720776f72642e",
            "0x0000000000000000000000000000000000000000000000000000000000000011",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array = ByteArray::try_from(data.unwrap()).unwrap();

        assert_eq!(
            byte_array.data,
            vec![
                Felt::from_str(
                    "0x00004c6f6e67206c6f6e6720737472696e672c2061206c6f74206d6f72652074",
                )
                .unwrap(),
                Felt::from_str(
                    "0x000068616e2033312063686172616374657273207468617420776f756c646e27",
                )
                .unwrap(),
                Felt::from_str(
                    "0x000074206576656e2066697420696e2074776f2066656c74732c20736f207765",
                )
                .unwrap(),
                Felt::from_str(
                    "0x0000276c6c2068617665206174206c656173742074776f2066656c747320616e",
                )
                .unwrap()
            ]
        );
        assert_eq!(
            byte_array.pending_word,
            Felt::from_str("0x0000000000000000000000000000006420612070656e64696e6720776f72642e",)
                .unwrap()
        );
        assert_eq!(byte_array.pending_word_length, 17);
    }

    #[test]
    fn try_from_valid_one_very_big_string() {
        // Example for a long string (doesn't fit in a single felt) taken from here:
        // https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
        //
        // So this is the string "Long string, more than 31 characters."
        let data: Result<Vec<Felt>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "0x004c6f6e6720737472696e672c206d6f7265207468616e203331206368617261",
            "0x000000000000000000000000000000000000000000000000000063746572732e",
            "0x0000000000000000000000000000000000000000000000000000000000000006",
        ]
        .into_iter()
        .map(Felt::from_str)
        .collect();

        let byte_array = ByteArray::try_from(data.unwrap()).unwrap();

        assert_eq!(
            byte_array.data,
            vec![Felt::from_str(
                "0x004c6f6e6720737472696e672c206d6f7265207468616e203331206368617261",
            )
            .unwrap()]
        );
        assert_eq!(
            byte_array.pending_word,
            Felt::from_str("0x000000000000000000000000000000000000000000000000000063746572732e",)
                .unwrap()
        );
        assert_eq!(byte_array.pending_word_length, 6);
    }
}
