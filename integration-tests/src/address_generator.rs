use std::cell::RefCell;
use std::num::NonZeroU64;
use std::rc::Rc;

use anyhow::Context;
use cosmwasm_std::{Addr, Api, CanonicalAddr, Storage};
use cw_multi_test::SimpleAddressGenerator;

/// Implements MultiTest's `AddressGenerator` trait for generating contract addresses by using the
/// default `SimpleAddressGenerator`, but also allows for predicting the next address, so you can
/// use the address in an `Instantiate` message without having to go through all of the `Instantiate2`
/// hoops.
///
/// To use this, you need to pass a clone of your instance to the WasmKeeper and keep the original
/// instance to access the next address prediction.
#[derive(Clone)]
pub struct AddressGenerator {
    inner: Rc<RefCell<AddressGenImpl>>,
}

impl Default for AddressGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressGenerator {
    /// Creates a new `AddressGenerator`.
    pub fn new() -> Self {
        AddressGenerator {
            inner: Rc::new(RefCell::new(AddressGenImpl {
                next_code_id: 0,
                next_instance_id: 0,
            })),
        }
    }

    /// Predicts the n-th contract address based on the current state of the generator.
    /// To get the next address, you can use `n = 1`.
    /// This assumes that the `n` next contract instantiations will follow the following pattern:
    /// store code 1 -> instantiate 1 -> store code 2 -> instantiate 2 ...
    pub fn future_address(
        &self,
        api: &dyn Api,
        storage: &mut dyn Storage,
        n: NonZeroU64,
    ) -> anyhow::Result<Addr> {
        let inner = self.inner.borrow();
        cw_multi_test::AddressGenerator::contract_address(
            &SimpleAddressGenerator,
            api,
            storage,
            // the clippy lint is incorrect here since n > 0 is guaranteed, and this is test code anyways
            #[allow(clippy::arithmetic_side_effects)]
            inner
                .next_code_id
                .checked_add(n.get() - 1)
                .context("code id overflow")?,
            #[allow(clippy::arithmetic_side_effects)]
            inner
                .next_instance_id
                .checked_add(n.get() - 1)
                .context("instance id overflow")?,
        )
    }
}

impl cw_multi_test::AddressGenerator for AddressGenerator {
    /// Generates a contract address based on the code ID and instance ID.
    fn contract_address(
        &self,
        api: &dyn Api,
        storage: &mut dyn Storage,
        code_id: u64,
        instance_id: u64,
    ) -> anyhow::Result<Addr> {
        let mut inner = self.inner.borrow_mut();
        inner.next_code_id = inner
            .next_code_id
            .max(code_id)
            .checked_add(1)
            .context("code id overflow")?;
        inner.next_instance_id = inner
            .next_instance_id
            .max(instance_id)
            .checked_add(1)
            .context("instance id overflow")?;

        SimpleAddressGenerator.contract_address(api, storage, code_id, instance_id)
    }

    /// Generates a predictable contract address based on the code ID and instance ID.
    fn predictable_contract_address(
        &self,
        api: &dyn Api,
        storage: &mut dyn Storage,
        code_id: u64,
        instance_id: u64,
        checksum: &[u8],
        creator: &CanonicalAddr,
        salt: &[u8],
    ) -> anyhow::Result<Addr> {
        SimpleAddressGenerator.predictable_contract_address(
            api,
            storage,
            code_id,
            instance_id,
            checksum,
            creator,
            salt,
        )
    }
}

struct AddressGenImpl {
    next_code_id: u64,
    next_instance_id: u64,
}
