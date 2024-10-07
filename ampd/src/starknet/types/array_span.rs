use starknet_core::types::{FieldElement, ValueOutOfRangeError};
use thiserror::Error;

/// Represents Cairo's Array and Span types.
/// Implements `TryFrom<Vec<FieldElement>>`, which is the way to create it.
///
/// ## Example usage with the string "hello"
///
/// ```rust
/// use ampd::starknet::types::array_span::ArraySpan;
/// use std::str::FromStr;
/// use starknet_core::types::FieldElement;
/// use starknet_core::types::FromStrError;
///
/// let data: Result<Vec<FieldElement>, FromStrError> = vec![
///         "0x0000000000000000000000000000000000000000000000000000000000000005",
///         "0x0000000000000000000000000000000000000000000000000000000000000068",
///         "0x0000000000000000000000000000000000000000000000000000000000000065",
///         "0x000000000000000000000000000000000000000000000000000000000000006c",
///         "0x000000000000000000000000000000000000000000000000000000000000006c",
///         "0x000000000000000000000000000000000000000000000000000000000000006f",
/// ]
///    .into_iter()
///    .map(FieldElement::from_str)
///    .collect();
///
/// let array_span = ArraySpan::<u8>::try_from(data.unwrap()).unwrap();
/// assert_eq!(array_span.data, vec![104, 101, 108, 108, 111]);
/// assert_eq!(String::from_utf8(array_span.data).unwrap(), "hello");
/// ```
///
/// For more info:
/// https://docs.starknet.io/documentation/architecture_and_concepts/Smart_Contracts/serialization_of_Cairo_types/#serialization_of_byte_arrays
#[derive(Debug)]
pub struct ArraySpan<T> {
    pub data: Vec<T>,
}

#[derive(Error, Debug)]
pub enum ArraySpanError {
    #[error("Invalid array/span length")]
    InvalidLength,
    #[error("Failed to parse felt - {0}")]
    ParsingFelt(#[from] ValueOutOfRangeError),
}

impl TryFrom<Vec<FieldElement>> for ArraySpan<u8> {
    type Error = ArraySpanError;

    fn try_from(data: Vec<FieldElement>) -> Result<Self, Self::Error> {
        // First element is always the array length, which is a felt (so u8 is enough)
        let arr_length = u8::try_from(data[0])?;

        // -1 because we have to offset the first element (the length itself)
        let arr_length_usize = usize::from(arr_length);
        if arr_length_usize != data.len().wrapping_sub(1) {
            return Err(ArraySpanError::InvalidLength);
        }

        let bytes: Result<Vec<u8>, ArraySpanError> = data
            .get(1..)
            .ok_or(ArraySpanError::InvalidLength)?
            .iter()
            .copied()
            .map(|e| e.try_into().map_err(ArraySpanError::ParsingFelt))
            .collect();

        Ok(ArraySpan { data: bytes? })
    }
}

#[cfg(test)]
mod array_span_tests {
    use std::str::FromStr;

    use starknet_core::types::{FieldElement, FromStrError};

    use crate::starknet::types::array_span::ArraySpan;

    #[test]
    fn try_from_valid_zeros() {
        // the string "hello", but FieldElement is bigger than u8::max
        let data = vec![FieldElement::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap()];

        let array_span = ArraySpan::<u8>::try_from(data).unwrap();
        assert_eq!(array_span.data, Vec::<u8>::new());
    }

    #[test]
    fn try_from_failed_to_parse_element_to_u8() {
        // the string "hello", but FieldElement is bigger than u8::max
        let data: Result<Vec<FieldElement>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000005",
            "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "0x0000000000000000000000000000000000000000000000000000000000000065",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006f",
        ]
        .into_iter()
        .map(FieldElement::from_str)
        .collect();

        let array_span = ArraySpan::<u8>::try_from(data.unwrap());
        assert!(array_span.is_err());
    }

    #[test]
    fn try_from_failed_to_parse_elements_length_to_u32() {
        // the string "hello", but element count is bigger than u32::max
        let data: Result<Vec<FieldElement>, FromStrError> = vec![
            "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "0x0000000000000000000000000000000000000000000000000000000000000068",
            "0x0000000000000000000000000000000000000000000000000000000000000065",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006f",
        ]
        .into_iter()
        .map(FieldElement::from_str)
        .collect();

        let array_span = ArraySpan::<u8>::try_from(data.unwrap());
        assert!(array_span.is_err());
    }

    #[test]
    fn try_from_invalid_number_of_elements() {
        // the string "hello", but with only 4 bytes
        let data: Result<Vec<FieldElement>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000005",
            "0x0000000000000000000000000000000000000000000000000000000000000068",
            "0x0000000000000000000000000000000000000000000000000000000000000065",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
        ]
        .into_iter()
        .map(FieldElement::from_str)
        .collect();

        let array_span = ArraySpan::<u8>::try_from(data.unwrap());
        assert!(array_span.is_err());
    }

    #[test]
    fn try_from_invalid_declared_length() {
        // the string "hello", with correct number of bytes, but only 4 declared,
        // instead of 5
        let data: Result<Vec<FieldElement>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000004",
            "0x0000000000000000000000000000000000000000000000000000000000000068",
            "0x0000000000000000000000000000000000000000000000000000000000000065",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006f",
        ]
        .into_iter()
        .map(FieldElement::from_str)
        .collect();

        let array_span = ArraySpan::<u8>::try_from(data.unwrap());
        assert!(array_span.is_err());
    }

    #[test]
    fn try_from_valid() {
        // the string "hello"
        let data: Result<Vec<FieldElement>, FromStrError> = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000005",
            "0x0000000000000000000000000000000000000000000000000000000000000068",
            "0x0000000000000000000000000000000000000000000000000000000000000065",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006c",
            "0x000000000000000000000000000000000000000000000000000000000000006f",
        ]
        .into_iter()
        .map(FieldElement::from_str)
        .collect();

        let array_span = ArraySpan::<u8>::try_from(data.unwrap()).unwrap();
        assert_eq!(array_span.data, vec![104, 101, 108, 108, 111]);
    }
}
