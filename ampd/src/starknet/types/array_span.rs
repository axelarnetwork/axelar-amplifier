use starknet_core::types::{FieldElement, ValueOutOfRangeError};
use thiserror::Error;

/// Applies for bot a cairo Array and a Span
#[derive(Debug)]
pub struct ArraySpan {
    pub bytes: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum ArraySpanError {
    #[error("Invalid array/span length")]
    InvalidLength,
    #[error("Failed to parse felt - {0}")]
    ParsingFelt(#[from] ValueOutOfRangeError),
}

impl TryFrom<Vec<FieldElement>> for ArraySpan {
    type Error = ArraySpanError;

    fn try_from(data: Vec<FieldElement>) -> Result<Self, Self::Error> {
        // First element is always the array length.
        // We also have to go from `u32` to usize, because
        // there's no direct `usize` From impl.
        let arr_length: u32 = match data[0].try_into() {
            Ok(al) => al,
            Err(err) => return Err(ArraySpanError::ParsingFelt(err)),
        };

        // -1 because we have to offset the first element (the length itself)
        let is_arr_el_count_valid = usize::try_from(arr_length)
            .map(|count| count == data.len() - 1)
            .unwrap_or(false);

        if !is_arr_el_count_valid {
            return Err(ArraySpanError::InvalidLength);
        }

        let bytes_parse: Result<Vec<u8>, ArraySpanError> = match data.get(1..) {
            Some(b) => b,
            None => return Err(ArraySpanError::InvalidLength),
        }
        .to_vec()
        .into_iter()
        .map(|e| {
            let word_count: u8 = match e.try_into() {
                Ok(wc) => wc,
                Err(err) => return Err(ArraySpanError::ParsingFelt(err)),
            };

            Ok(word_count)
        })
        .collect();

        let bytes = match bytes_parse {
            Ok(b) => b,
            Err(e) => return Err(e),
        };

        Ok(ArraySpan { bytes })
    }
}

#[cfg(test)]
mod array_span_tests {
    use std::str::FromStr;

    use starknet_core::types::FieldElement;

    use crate::starknet::types::array_span::ArraySpan;

    #[test]
    fn try_from_valid_zeros() {
        // the string "hello", but FieldElement is bigger than u8::max
        let data = vec![FieldElement::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap()];

        let array_span = ArraySpan::try_from(data).unwrap();
        assert_eq!(array_span.bytes, Vec::<u8>::new());
    }

    #[test]
    fn try_from_failed_to_parse_element_to_u8() {
        // the string "hello", but FieldElement is bigger than u8::max
        let data = vec![
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000005",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000065",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006f",
            )
            .unwrap(),
        ];

        let array_span = ArraySpan::try_from(data);
        assert!(array_span.is_err());
    }

    #[test]
    fn try_from_failed_to_parse_elements_length_to_u32() {
        // the string "hello", but element counte bigger than u32::max
        let data = vec![
            FieldElement::from_str(
                "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000068",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000065",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006f",
            )
            .unwrap(),
        ];

        let array_span = ArraySpan::try_from(data);
        assert!(array_span.is_err());
    }

    #[test]
    fn try_from_invalid_number_of_elements() {
        // the string "hello", but with only 4 bytes
        let data = vec![
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000005",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000068",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000065",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
        ];

        let array_span = ArraySpan::try_from(data);
        assert!(array_span.is_err());
    }

    #[test]
    fn try_from_invalid_declared_length() {
        // the string "hello", with correct number of bytes, but only 4 declared,
        // instead of 5
        let data = vec![
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000068",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000065",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006f",
            )
            .unwrap(),
        ];

        let array_span = ArraySpan::try_from(data);
        assert!(array_span.is_err());
    }

    #[test]
    fn try_from_valid() {
        // the string "hello"
        let data = vec![
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000005",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000068",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000065",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006c",
            )
            .unwrap(),
            FieldElement::from_str(
                "0x000000000000000000000000000000000000000000000000000000000000006f",
            )
            .unwrap(),
        ];

        let array_span = ArraySpan::try_from(data).unwrap();
        assert_eq!(array_span.bytes, vec![104, 101, 108, 108, 111]);
    }
}
