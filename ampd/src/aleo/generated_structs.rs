#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractCall<N: snarkvm::prelude::Network> {
    pub caller: snarkvm::prelude::Address<N>,
    pub sender: snarkvm::prelude::Address<N>,
    pub destination_chain: [u128; 2usize],
    pub destination_address: [u128; 6usize],
    pub payload_hash: snarkvm::prelude::Field<N>,
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for ContractCall<N> {
    fn default() -> Self {
        Self {
            caller: snarkvm::prelude::Address::<N>::zero(),
            sender: snarkvm::prelude::Address::<N>::zero(),
            destination_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
            destination_address: ::std::array::from_fn(|_| ::std::default::Default::default()),
            payload_hash: snarkvm::prelude::Field::default(),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&ContractCall<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &ContractCall<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert(
                "caller".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::Address(value.caller)),
            );
        }
        {
            map.insert(
                "sender".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::Address(value.sender)),
            );
        }
        {
            map.insert("destination_chain".parse()?, {
                let elements = value
                    .destination_chain
                    .iter()
                    .map(
                        |element| -> anyhow::Result<snarkvm::prelude::Plaintext<N>> {
                            Ok(snarkvm::prelude::Plaintext::from(
                                snarkvm::prelude::Literal::U128(snarkvm::prelude::U128::new(
                                    *element,
                                )),
                            ))
                        },
                    )
                    .collect::<anyhow::Result<Vec<_>>>()?;
                snarkvm::prelude::Plaintext::Array(elements, ::std::default::Default::default())
            });
        }
        {
            map.insert("destination_address".parse()?, {
                let elements = value
                    .destination_address
                    .iter()
                    .map(
                        |element| -> anyhow::Result<snarkvm::prelude::Plaintext<N>> {
                            Ok(snarkvm::prelude::Plaintext::from(
                                snarkvm::prelude::Literal::U128(snarkvm::prelude::U128::new(
                                    *element,
                                )),
                            ))
                        },
                    )
                    .collect::<anyhow::Result<Vec<_>>>()?;
                snarkvm::prelude::Plaintext::Array(elements, ::std::default::Default::default())
            });
        }
        {
            map.insert(
                "payload_hash".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::Field(
                    value.payload_hash,
                )),
            );
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&ContractCall<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &ContractCall<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for ContractCall<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let caller = {
            let key: snarkvm::prelude::Identifier<N> = "caller".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "caller"))?;
            let result: anyhow::Result<snarkvm::prelude::Address<N>> = {
                let member_name = "caller";
                let snarkvm::prelude::Plaintext::Literal(
                    snarkvm::prelude::Literal::Address(val),
                    _,
                ) = value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let sender = {
            let key: snarkvm::prelude::Identifier<N> = "sender".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "sender"))?;
            let result: anyhow::Result<snarkvm::prelude::Address<N>> = {
                let member_name = "sender";
                let snarkvm::prelude::Plaintext::Literal(
                    snarkvm::prelude::Literal::Address(val),
                    _,
                ) = value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let destination_chain = {
            let key: snarkvm::prelude::Identifier<N> = "destination_chain".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "destination_chain"))?;
            let result: anyhow::Result<[u128; 2usize]> = {
                let member_name = "destination_chain";
                let snarkvm::prelude::Plaintext::Array(elements, _) = value else {
                    anyhow::bail!("Expected a Plaintext::Array for member '{member_name}'");
                };
                if elements.len() != 2usize {
                    anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize,
                        elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: anyhow::Result<u128> = {
                            let snarkvm::prelude::Plaintext::Literal(
                                snarkvm::prelude::Literal::U128(val),
                                _,
                            ) = value
                            else {
                                anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let destination_address = {
            let key: snarkvm::prelude::Identifier<N> = "destination_address".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "destination_address"))?;
            let result: anyhow::Result<[u128; 6usize]> = {
                let member_name = "destination_address";
                let snarkvm::prelude::Plaintext::Array(elements, _) = value else {
                    anyhow::bail!("Expected a Plaintext::Array for member '{member_name}'");
                };
                if elements.len() != 6usize {
                    anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize,
                        elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: anyhow::Result<u128> = {
                            let snarkvm::prelude::Plaintext::Literal(
                                snarkvm::prelude::Literal::U128(val),
                                _,
                            ) = value
                            else {
                                anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let payload_hash = {
            let key: snarkvm::prelude::Identifier<N> = "payload_hash".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "payload_hash"))?;
            let result: anyhow::Result<snarkvm::prelude::Field<N>> = {
                let member_name = "payload_hash";
                let snarkvm::prelude::Plaintext::Literal(snarkvm::prelude::Literal::Field(val), _) =
                    value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Field"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self {
            caller,
            sender,
            destination_chain,
            destination_address,
            payload_hash,
        })
    }
}
