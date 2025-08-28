use cosmwasm_schema::cw_serde;

const LIMIT_MAX: u32 = u32::MAX;
const LIMIT_MIN: u32 = 1;

#[cw_serde]
pub struct Limit(u32);

impl Limit {
    #[allow(dead_code)]
    fn min() -> Self {
        Limit(LIMIT_MIN)
    }

    #[allow(dead_code)]
    fn max() -> Self {
        Limit(LIMIT_MAX)
    }
}

impl From<u32> for Limit {
    fn from(value: u32) -> Self {
        if value == 0 {
            panic!("limit must be between {} and {}", LIMIT_MIN, LIMIT_MAX);
        }

        Limit(value)
    }
}

impl From<Limit> for usize {
    fn from(value: Limit) -> Self {
        value.0 as usize
    }
}

#[cfg(test)]
pub mod test {
    use crate::Limit;

    #[test]
    #[should_panic]
    fn limit_should_panic_on_zero_value() {
        let _ = Limit::from(0);
    }

    #[test]
    fn limit_max_is_u32_max_succeeds() {
        let max_limit: usize = Limit::max().into();
        assert_eq!(max_limit, u32::MAX as usize);
    }

    #[test]
    fn limit_min_is_one() {
        let min_limit: usize = Limit::min().into();
        assert_eq!(min_limit, 1);
    }
}
