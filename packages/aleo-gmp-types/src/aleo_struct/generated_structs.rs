use snarkvm_cosmwasm as snarkvm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<N: snarkvm::prelude::Network> {
    pub source_chain: [u128; 2usize],
    pub message_id: [u128; 8usize],
    pub source_address: [u128; 6usize],
    pub contract_address: snarkvm::prelude::Address<N>,
    pub payload_hash: snarkvm::prelude::Group<N>,
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for Message<N> {
    fn default() -> Self {
        Self {
            source_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
            message_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            source_address: ::std::array::from_fn(|_| ::std::default::Default::default()),
            contract_address: snarkvm::prelude::Address::<N>::zero(),
            payload_hash: <snarkvm::prelude::Group<N> as snarkvm::prelude::Zero>::zero(),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&Message<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &Message<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert("source_chain".parse()?, {
                let elements = value
                    .source_chain
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
            map.insert("message_id".parse()?, {
                let elements = value
                    .message_id
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
            map.insert("source_address".parse()?, {
                let elements = value
                    .source_address
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
                "contract_address".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::Address(
                    value.contract_address,
                )),
            );
        }
        {
            map.insert(
                "payload_hash".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::Group(
                    value.payload_hash,
                )),
            );
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&Message<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &Message<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for Message<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let source_chain = {
            let key: snarkvm::prelude::Identifier<N> = "source_chain".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "source_chain"))?;
            let result: anyhow::Result<[u128; 2usize]> = {
                let member_name = "source_chain";
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
        let message_id = {
            let key: snarkvm::prelude::Identifier<N> = "message_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "message_id"))?;
            let result: anyhow::Result<[u128; 8usize]> = {
                let member_name = "message_id";
                let snarkvm::prelude::Plaintext::Array(elements, _) = value else {
                    anyhow::bail!("Expected a Plaintext::Array for member '{member_name}'");
                };
                if elements.len() != 8usize {
                    anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        8usize,
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
                let arr: [u128; 8usize] = converted_elements
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let source_address = {
            let key: snarkvm::prelude::Identifier<N> = "source_address".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "source_address"))?;
            let result: anyhow::Result<[u128; 6usize]> = {
                let member_name = "source_address";
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
        let contract_address = {
            let key: snarkvm::prelude::Identifier<N> = "contract_address".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "contract_address"))?;
            let result: anyhow::Result<snarkvm::prelude::Address<N>> = {
                let member_name = "contract_address";
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
        let payload_hash = {
            let key: snarkvm::prelude::Identifier<N> = "payload_hash".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "payload_hash"))?;
            let result: anyhow::Result<snarkvm::prelude::Group<N>> = {
                let member_name = "payload_hash";
                let snarkvm::prelude::Plaintext::Literal(snarkvm::prelude::Literal::Group(val), _) =
                    value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Group"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self {
            source_chain,
            message_id,
            source_address,
            contract_address,
            payload_hash,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Messages<N: snarkvm::prelude::Network> {
    pub messages: [[Message<N>; 24usize]; 2usize],
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for Messages<N> {
    fn default() -> Self {
        Self {
            messages: ::std::array::from_fn(|_| {
                ::std::array::from_fn(|_| ::std::default::Default::default())
            }),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&Messages<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &Messages<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert("messages".parse()?, {
                let elements = value
                    .messages
                    .iter()
                    .map(
                        |element| -> anyhow::Result<snarkvm::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> anyhow::Result<
                                        snarkvm::prelude::Plaintext<N>,
                                    > {
                                        snarkvm::prelude::Plaintext::try_from(
                                            element,
                                        )
                                    })
                                    .collect::<anyhow::Result<Vec<_>>>()?;
                                snarkvm::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        },
                    )
                    .collect::<anyhow::Result<Vec<_>>>()?;
                snarkvm::prelude::Plaintext::Array(elements, ::std::default::Default::default())
            });
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&Messages<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &Messages<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for Messages<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let messages = {
            let key: snarkvm::prelude::Identifier<N> = "messages".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "messages"))?;
            let result: anyhow::Result<[[Message<N>; 24usize]; 2usize]> = {
                let member_name = "messages";
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
                        let result: anyhow::Result<
                            [Message<N>; 24usize],
                        > = {
                            let snarkvm::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 24usize {
                                anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    24usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: anyhow::Result<
                                        Message<N>,
                                    > = {
                                        Ok(
                                            Message::try_from(value)
                                                .map_err(|e| {
                                                    anyhow::anyhow!(
                                                        "Failed to convert Plaintext to {}({}): {}",
                                                        stringify!(Message), member_name, e
                                                    )
                                                })?,
                                        )
                                    };
                                    result
                                })
                                .collect::<anyhow::Result<Vec<_>>>()?;
                            let arr: [Message<N>; 24usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "Failed to convert Vec to array"
                                    )
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let arr: [[Message<N>; 24usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self { messages })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageGroup<N: snarkvm::prelude::Network> {
    pub messages: [[snarkvm::prelude::Group<N>; 24usize]; 2usize],
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for MessageGroup<N> {
    fn default() -> Self {
        Self {
            messages: ::std::array::from_fn(|_| {
                ::std::array::from_fn(|_| {
                    <snarkvm::prelude::Group<N> as snarkvm::prelude::Zero>::zero()
                })
            }),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&MessageGroup<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &MessageGroup<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert("messages".parse()?, {
                let elements = value
                    .messages
                    .iter()
                    .map(
                        |element| -> anyhow::Result<snarkvm::prelude::Plaintext<N>> {
                            Ok({
                                let elements =
                                        element
                                            .iter()
                                            .map(
                                                |element| -> anyhow::Result<
                                                    snarkvm::prelude::Plaintext<N>,
                                                > {
                                                    Ok(snarkvm::prelude::Plaintext::from(
                                                        snarkvm::prelude::Literal::Group(*element),
                                                    ))
                                                },
                                            )
                                            .collect::<anyhow::Result<Vec<_>>>()?;
                                snarkvm::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        },
                    )
                    .collect::<anyhow::Result<Vec<_>>>()?;
                snarkvm::prelude::Plaintext::Array(elements, ::std::default::Default::default())
            });
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&MessageGroup<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &MessageGroup<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for MessageGroup<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let messages = {
            let key: snarkvm::prelude::Identifier<N> = "messages".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "messages"))?;
            let result: anyhow::Result<[[snarkvm::prelude::Group<N>; 24usize]; 2usize]> = {
                let member_name = "messages";
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
                        let result: anyhow::Result<
                            [snarkvm::prelude::Group<N>; 24usize],
                        > = {
                            let snarkvm::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 24usize {
                                anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    24usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: anyhow::Result<
                                        snarkvm::prelude::Group<N>,
                                    > = {
                                        let snarkvm::prelude::Plaintext::Literal(
                                            snarkvm::prelude::Literal::Group(val),
                                            _,
                                        ) = value else {
                                            anyhow::bail!(
                                                "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                                "Group"
                                            );
                                        };
                                        Ok(*val)
                                    };
                                    result
                                })
                                .collect::<anyhow::Result<Vec<_>>>()?;
                            let arr: [snarkvm::prelude::Group<
                                N,
                            >; 24usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "Failed to convert Vec to array"
                                    )
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let arr: [[snarkvm::prelude::Group<N>; 24usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self { messages })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadDigest<N: snarkvm::prelude::Network> {
    pub domain_separator: [u128; 2usize],
    pub signer: WeightedSigners<N>,
    pub data_hash: snarkvm::prelude::Group<N>,
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for PayloadDigest<N> {
    fn default() -> Self {
        Self {
            domain_separator: ::std::array::from_fn(|_| ::std::default::Default::default()),
            signer: ::std::default::Default::default(),
            data_hash: <snarkvm::prelude::Group<N> as snarkvm::prelude::Zero>::zero(),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&PayloadDigest<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &PayloadDigest<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert("domain_separator".parse()?, {
                let elements = value
                    .domain_separator
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
                "signer".parse()?,
                snarkvm::prelude::Plaintext::try_from(&value.signer)?,
            );
        }
        {
            map.insert(
                "data_hash".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::Group(
                    value.data_hash,
                )),
            );
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&PayloadDigest<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &PayloadDigest<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for PayloadDigest<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let domain_separator = {
            let key: snarkvm::prelude::Identifier<N> = "domain_separator".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "domain_separator"))?;
            let result: anyhow::Result<[u128; 2usize]> = {
                let member_name = "domain_separator";
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
        let signer = {
            let key: snarkvm::prelude::Identifier<N> = "signer".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "signer"))?;
            let result: anyhow::Result<WeightedSigners<N>> = {
                let member_name = "signer";
                Ok(WeightedSigners::try_from(value).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to convert Plaintext to {}({}): {}",
                        stringify!(WeightedSigners),
                        member_name,
                        e
                    )
                })?)
            };
            result?
        };
        let data_hash = {
            let key: snarkvm::prelude::Identifier<N> = "data_hash".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "data_hash"))?;
            let result: anyhow::Result<snarkvm::prelude::Group<N>> = {
                let member_name = "data_hash";
                let snarkvm::prelude::Plaintext::Literal(snarkvm::prelude::Literal::Group(val), _) =
                    value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Group"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self {
            domain_separator,
            signer,
            data_hash,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteData<N: snarkvm::prelude::Network> {
    pub proof: Proof<N>,
    pub message: Messages<N>,
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for ExecuteData<N> {
    fn default() -> Self {
        Self {
            proof: ::std::default::Default::default(),
            message: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&ExecuteData<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &ExecuteData<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert(
                "proof".parse()?,
                snarkvm::prelude::Plaintext::try_from(&value.proof)?,
            );
        }
        {
            map.insert(
                "message".parse()?,
                snarkvm::prelude::Plaintext::try_from(&value.message)?,
            );
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&ExecuteData<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &ExecuteData<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for ExecuteData<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let proof = {
            let key: snarkvm::prelude::Identifier<N> = "proof".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "proof"))?;
            let result: anyhow::Result<Proof<N>> = {
                let member_name = "proof";
                Ok(Proof::try_from(value).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to convert Plaintext to {}({}): {}",
                        stringify!(Proof),
                        member_name,
                        e
                    )
                })?)
            };
            result?
        };
        let message = {
            let key: snarkvm::prelude::Identifier<N> = "message".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "message"))?;
            let result: anyhow::Result<Messages<N>> = {
                let member_name = "message";
                Ok(Messages::try_from(value).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to convert Plaintext to {}({}): {}",
                        stringify!(Messages),
                        member_name,
                        e
                    )
                })?)
            };
            result?
        };
        Ok(Self { proof, message })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteDataVerifierSet<N: snarkvm::prelude::Network> {
    pub proof: Proof<N>,
    pub payload: WeightedSigners<N>,
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for ExecuteDataVerifierSet<N> {
    fn default() -> Self {
        Self {
            proof: ::std::default::Default::default(),
            payload: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&ExecuteDataVerifierSet<N>>
    for snarkvm::prelude::Plaintext<N>
{
    type Error = anyhow::Error;
    fn try_from(value: &ExecuteDataVerifierSet<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert(
                "proof".parse()?,
                snarkvm::prelude::Plaintext::try_from(&value.proof)?,
            );
        }
        {
            map.insert(
                "payload".parse()?,
                snarkvm::prelude::Plaintext::try_from(&value.payload)?,
            );
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&ExecuteDataVerifierSet<N>>
    for snarkvm::prelude::Value<N>
{
    type Error = anyhow::Error;
    fn try_from(value: &ExecuteDataVerifierSet<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>>
    for ExecuteDataVerifierSet<N>
{
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let proof = {
            let key: snarkvm::prelude::Identifier<N> = "proof".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "proof"))?;
            let result: anyhow::Result<Proof<N>> = {
                let member_name = "proof";
                Ok(Proof::try_from(value).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to convert Plaintext to {}({}): {}",
                        stringify!(Proof),
                        member_name,
                        e
                    )
                })?)
            };
            result?
        };
        let payload = {
            let key: snarkvm::prelude::Identifier<N> = "payload".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "payload"))?;
            let result: anyhow::Result<WeightedSigners<N>> = {
                let member_name = "payload";
                Ok(WeightedSigners::try_from(value).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to convert Plaintext to {}({}): {}",
                        stringify!(WeightedSigners),
                        member_name,
                        e
                    )
                })?)
            };
            result?
        };
        Ok(Self { proof, payload })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignersRotated<N: snarkvm::prelude::Network> {
    pub new_signers_hash: snarkvm::prelude::Group<N>,
    pub new_signers_data: WeightedSigners<N>,
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for SignersRotated<N> {
    fn default() -> Self {
        Self {
            new_signers_hash: <snarkvm::prelude::Group<N> as snarkvm::prelude::Zero>::zero(),
            new_signers_data: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&SignersRotated<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &SignersRotated<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert(
                "new_signers_hash".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::Group(
                    value.new_signers_hash,
                )),
            );
        }
        {
            map.insert(
                "new_signers_data".parse()?,
                snarkvm::prelude::Plaintext::try_from(&value.new_signers_data)?,
            );
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&SignersRotated<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &SignersRotated<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for SignersRotated<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let new_signers_hash = {
            let key: snarkvm::prelude::Identifier<N> = "new_signers_hash".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "new_signers_hash"))?;
            let result: anyhow::Result<snarkvm::prelude::Group<N>> = {
                let member_name = "new_signers_hash";
                let snarkvm::prelude::Plaintext::Literal(snarkvm::prelude::Literal::Group(val), _) =
                    value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Group"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let new_signers_data = {
            let key: snarkvm::prelude::Identifier<N> = "new_signers_data".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "new_signers_data"))?;
            let result: anyhow::Result<WeightedSigners<N>> = {
                let member_name = "new_signers_data";
                Ok(WeightedSigners::try_from(value).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to convert Plaintext to {}({}): {}",
                        stringify!(WeightedSigners),
                        member_name,
                        e
                    )
                })?)
            };
            result?
        };
        Ok(Self {
            new_signers_hash,
            new_signers_data,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedSigner<N: snarkvm::prelude::Network> {
    pub addr: snarkvm::prelude::Address<N>,
    pub weight: u128,
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for WeightedSigner<N> {
    fn default() -> Self {
        Self {
            addr: snarkvm::prelude::Address::<N>::zero(),
            weight: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&WeightedSigner<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &WeightedSigner<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert(
                "addr".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::Address(value.addr)),
            );
        }
        {
            map.insert(
                "weight".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::U128(
                    snarkvm::prelude::U128::new(value.weight),
                )),
            );
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&WeightedSigner<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &WeightedSigner<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for WeightedSigner<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let addr = {
            let key: snarkvm::prelude::Identifier<N> = "addr".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "addr"))?;
            let result: anyhow::Result<snarkvm::prelude::Address<N>> = {
                let member_name = "addr";
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
        let weight = {
            let key: snarkvm::prelude::Identifier<N> = "weight".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "weight"))?;
            let result: anyhow::Result<u128> = {
                let member_name = "weight";
                let snarkvm::prelude::Plaintext::Literal(snarkvm::prelude::Literal::U128(val), _) =
                    value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        Ok(Self { addr, weight })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedSigners<N: snarkvm::prelude::Network> {
    pub signers: [[WeightedSigner<N>; 14usize]; 2usize],
    pub quorum: u128,
    pub nonce: u64,
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for WeightedSigners<N> {
    fn default() -> Self {
        Self {
            signers: ::std::array::from_fn(|_| {
                ::std::array::from_fn(|_| ::std::default::Default::default())
            }),
            quorum: ::std::default::Default::default(),
            nonce: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&WeightedSigners<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &WeightedSigners<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert("signers".parse()?, {
                let elements = value
                    .signers
                    .iter()
                    .map(
                        |element| -> anyhow::Result<snarkvm::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> anyhow::Result<
                                        snarkvm::prelude::Plaintext<N>,
                                    > {
                                        snarkvm::prelude::Plaintext::try_from(
                                            element,
                                        )
                                    })
                                    .collect::<anyhow::Result<Vec<_>>>()?;
                                snarkvm::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        },
                    )
                    .collect::<anyhow::Result<Vec<_>>>()?;
                snarkvm::prelude::Plaintext::Array(elements, ::std::default::Default::default())
            });
        }
        {
            map.insert(
                "quorum".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::U128(
                    snarkvm::prelude::U128::new(value.quorum),
                )),
            );
        }
        {
            map.insert(
                "nonce".parse()?,
                snarkvm::prelude::Plaintext::from(snarkvm::prelude::Literal::U64(
                    snarkvm::prelude::U64::new(value.nonce),
                )),
            );
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&WeightedSigners<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &WeightedSigners<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for WeightedSigners<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let signers = {
            let key: snarkvm::prelude::Identifier<N> = "signers".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "signers"))?;
            let result: anyhow::Result<[[WeightedSigner<N>; 14usize]; 2usize]> = {
                let member_name = "signers";
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
                        let result: anyhow::Result<
                            [WeightedSigner<N>; 14usize],
                        > = {
                            let snarkvm::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 14usize {
                                anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    14usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: anyhow::Result<
                                        WeightedSigner<N>,
                                    > = {
                                        Ok(
                                            WeightedSigner::try_from(value)
                                                .map_err(|e| {
                                                    anyhow::anyhow!(
                                                        "Failed to convert Plaintext to {}({}): {}",
                                                        stringify!(WeightedSigner), member_name, e
                                                    )
                                                })?,
                                        )
                                    };
                                    result
                                })
                                .collect::<anyhow::Result<Vec<_>>>()?;
                            let arr: [WeightedSigner<N>; 14usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "Failed to convert Vec to array"
                                    )
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let arr: [[WeightedSigner<N>; 14usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let quorum = {
            let key: snarkvm::prelude::Identifier<N> = "quorum".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "quorum"))?;
            let result: anyhow::Result<u128> = {
                let member_name = "quorum";
                let snarkvm::prelude::Plaintext::Literal(snarkvm::prelude::Literal::U128(val), _) =
                    value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let nonce = {
            let key: snarkvm::prelude::Identifier<N> = "nonce".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "nonce"))?;
            let result: anyhow::Result<u64> = {
                let member_name = "nonce";
                let snarkvm::prelude::Plaintext::Literal(snarkvm::prelude::Literal::U64(val), _) =
                    value
                else {
                    anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U64"
                    );
                };
                Ok(**val)
            };
            result?
        };
        Ok(Self {
            signers,
            quorum,
            nonce,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof<N: snarkvm::prelude::Network> {
    pub weighted_signers: WeightedSigners<N>,
    pub signatures: [[::std::boxed::Box<snarkvm::prelude::Signature<N>>; 14usize]; 2usize],
}
impl<N: snarkvm::prelude::Network> ::std::default::Default for Proof<N> {
    fn default() -> Self {
        Self {
            weighted_signers: ::std::default::Default::default(),
            signatures: ::std::array::from_fn(|_| {
                ::std::array::from_fn(|_| {
                    ::std::boxed::Box::new(snarkvm::prelude::Signature::from((
                        <snarkvm::prelude::Scalar<N> as snarkvm::prelude::Zero>::zero(),
                        <snarkvm::prelude::Scalar<N> as snarkvm::prelude::Zero>::zero(),
                        snarkvm::prelude::ComputeKey::try_from((
                            <snarkvm::prelude::Group<N> as snarkvm::prelude::Zero>::zero(),
                            <snarkvm::prelude::Group<N> as snarkvm::prelude::Zero>::zero(),
                        ))
                        .unwrap(),
                    )))
                })
            }),
        }
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&Proof<N>> for snarkvm::prelude::Plaintext<N> {
    type Error = anyhow::Error;
    fn try_from(value: &Proof<N>) -> anyhow::Result<Self, Self::Error> {
        let mut map = indexmap::IndexMap::new();
        {
            map.insert(
                "weighted_signers".parse()?,
                snarkvm::prelude::Plaintext::try_from(&value.weighted_signers)?,
            );
        }
        {
            map.insert("signatures".parse()?, {
                let elements = value
                    .signatures
                    .iter()
                    .map(
                        |element| -> anyhow::Result<snarkvm::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> anyhow::Result<
                                        snarkvm::prelude::Plaintext<N>,
                                    > {
                                        Ok(
                                            snarkvm::prelude::Plaintext::from(
                                                snarkvm::prelude::Literal::Signature(
                                                    (*element).clone(),
                                                ),
                                            ),
                                        )
                                    })
                                    .collect::<anyhow::Result<Vec<_>>>()?;
                                snarkvm::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        },
                    )
                    .collect::<anyhow::Result<Vec<_>>>()?;
                snarkvm::prelude::Plaintext::Array(elements, ::std::default::Default::default())
            });
        }
        let plaintext = snarkvm::prelude::Plaintext::Struct(map, once_cell::sync::OnceCell::new());
        Ok(plaintext)
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&Proof<N>> for snarkvm::prelude::Value<N> {
    type Error = anyhow::Error;
    fn try_from(value: &Proof<N>) -> anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm::prelude::Network> TryFrom<&snarkvm::prelude::Plaintext<N>> for Proof<N> {
    type Error = anyhow::Error;
    fn try_from(value: &snarkvm::prelude::Plaintext<N>) -> anyhow::Result<Self, Self::Error> {
        let snarkvm::prelude::Plaintext::Struct(map, _) = value else {
            anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let weighted_signers = {
            let key: snarkvm::prelude::Identifier<N> = "weighted_signers".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "weighted_signers"))?;
            let result: anyhow::Result<WeightedSigners<N>> = {
                let member_name = "weighted_signers";
                Ok(WeightedSigners::try_from(value).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to convert Plaintext to {}({}): {}",
                        stringify!(WeightedSigners),
                        member_name,
                        e
                    )
                })?)
            };
            result?
        };
        let signatures = {
            let key: snarkvm::prelude::Identifier<N> = "signatures".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("Missing member '{}'", "signatures"))?;
            let result: anyhow::Result<
                [[::std::boxed::Box<snarkvm::prelude::Signature<N>>; 14usize]; 2usize],
            > = {
                let member_name = "signatures";
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
                        let result: anyhow::Result<
                            [::std::boxed::Box<
                                snarkvm::prelude::Signature<N>,
                            >; 14usize],
                        > = {
                            let snarkvm::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 14usize {
                                anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    14usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: anyhow::Result<
                                        ::std::boxed::Box<
                                            snarkvm::prelude::Signature<N>,
                                        >,
                                    > = {
                                        let snarkvm::prelude::Plaintext::Literal(
                                            snarkvm::prelude::Literal::Signature(
                                                val,
                                            ),
                                            _,
                                        ) = value else {
                                            anyhow::bail!(
                                                "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                                "Signature"
                                            );
                                        };
                                        Ok(val.clone())
                                    };
                                    result
                                })
                                .collect::<anyhow::Result<Vec<_>>>()?;
                            let arr: [::std::boxed::Box<
                                snarkvm::prelude::Signature<N>,
                            >; 14usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "Failed to convert Vec to array"
                                    )
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let arr: [[::std::boxed::Box<snarkvm::prelude::Signature<N>>; 14usize]; 2usize] =
                    converted_elements
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self {
            weighted_signers,
            signatures,
        })
    }
}
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
