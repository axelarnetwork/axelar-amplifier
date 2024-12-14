use crypto_bigint::U256;
use starknet_types_core::felt::Felt;

pub trait TryMapExt<T> {
    type Monad<B>;
    fn try_map<B, E>(self, func: impl FnMut(T) -> Result<B, E>) -> Result<Self::Monad<B>, E>;
}

impl<T> TryMapExt<T> for Option<T> {
    type Monad<B> = Option<B>;

    fn try_map<B, E>(self, func: impl FnMut(T) -> Result<B, E>) -> Result<Option<B>, E> {
        self.map(func).transpose()
    }
}

impl<T> TryMapExt<T> for Vec<T> {
    type Monad<B> = Vec<B>;

    fn try_map<B, E>(self, func: impl FnMut(T) -> Result<B, E>) -> Result<Vec<B>, E> {
        self.into_iter().map(func).collect::<Result<Vec<B>, E>>()
    }
}

/// since the `Felt` type doesn't error on overflow, we have to implement that check
pub fn does_felt_overflow_from_slice(felt_hex_slice: &[u8]) -> bool {
    if felt_hex_slice.len() > 32 {
        return true;
    }
    let felt_max_hex_str = format!("{:064x}", Felt::MAX);
    U256::from_be_slice(felt_hex_slice) > U256::from_be_hex(&felt_max_hex_str)
}

/// since the `Felt` type doesn't error on overflow, we have to implement that check
pub fn does_felt_overflow_from_str(felt_hex_str: &str) -> bool {
    let felt_hex_str = felt_hex_str.trim_start_matches("0x");
    let felt_max_hex_str = format!("{:064x}", Felt::MAX);
    U256::from_be_hex(felt_hex_str) > U256::from_be_hex(&felt_max_hex_str)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_try_map_vec() {
        let vec = vec![1, 2, 3];
        let result: Result<_, &str> = vec.try_map(|x| Ok(x + 1));
        assert_eq!(result, Ok(vec![2, 3, 4]));

        let vec = vec![1, 2, 3];
        let result: Result<Vec<i32>, _> = vec.try_map(|_| Err("error"));
        assert_eq!(result, Err("error"));
    }

    #[test]
    fn test_try_map_option() {
        let option = Some(1);
        let result: Result<_, &str> = option.try_map(|x| Ok(x + 1));
        assert_eq!(result, Ok(Some(2)));

        let option = Some(1);
        let result: Result<Option<i32>, _> = option.try_map(|_| Err("error"));
        assert_eq!(result, Err("error"));
    }
}
