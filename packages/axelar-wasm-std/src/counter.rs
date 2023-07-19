use std::ops::AddAssign;

use cosmwasm_std::{StdResult, Storage};
use cw_storage_plus::Item;
use num_traits::One;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct Counter<'a, T: AddAssign + Copy + Default> {
    item: Item<'a, T>,
}

impl<'a, T: AddAssign + Copy + Default + One + Serialize + DeserializeOwned> Counter<'a, T> {
    pub const fn new(name: &'a str) -> Self {
        Counter {
            item: Item::new(name),
        }
    }

    pub fn cur(&self, store: &dyn Storage) -> T {
        self.item.load(store).unwrap_or_default()
    }

    pub fn incr(&self, store: &mut dyn Storage) -> StdResult<T> {
        let mut value = self.cur(store);
        value += T::one();
        self.item.save(store, &value)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::MockStorage;

    use super::*;

    #[test]
    fn test_get_and_incr() {
        let mut store = MockStorage::new();

        let counter: Counter<u64> = Counter::new("counter");
        assert_eq!(counter.cur(&store), 0);
        assert_eq!(counter.incr(&mut store).unwrap(), 1);
        assert_eq!(counter.incr(&mut store).unwrap(), 2);
        assert_eq!(counter.cur(&mut store), 2);
    }
}
