use snarkvm_cosmwasm as snarkvm_backend;
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Field < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct RegisterTokenMetadata<N: snarkvm_backend::prelude::Network> {
    pub decimals: u8,
    pub token_address: snarkvm_backend::prelude::Field<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for RegisterTokenMetadata<N> {
    fn default() -> Self {
        Self {
            decimals: ::std::default::Default::default(),
            token_address: snarkvm_backend::prelude::Field::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&RegisterTokenMetadata<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &RegisterTokenMetadata<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "decimals".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U8(
                        snarkvm_backend::prelude::U8::new(value.decimals),
                    ),
                ),
            );
        }
        {
            map.insert(
                "token_address".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Field(value.token_address),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<RegisterTokenMetadata<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: RegisterTokenMetadata<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&RegisterTokenMetadata<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &RegisterTokenMetadata<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<RegisterTokenMetadata<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: RegisterTokenMetadata<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for RegisterTokenMetadata<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let decimals = {
            let key: snarkvm_backend::prelude::Identifier<N> = "decimals".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "decimals"))?;
            let result: ::anyhow::Result<u8> = {
                let member_name = "decimals";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U8(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U8"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let token_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "token_address".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "token_address")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Field<N>> = {
                let member_name = "token_address";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Field(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Field"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self { decimals, token_address })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for RegisterTokenMetadata<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for RegisterTokenMetadata<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "WeightedSigners < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct RotateSignersInputs<N: snarkvm_backend::prelude::Network> {
    pub weighted_signers: WeightedSigners<N>,
    pub signatures: [[::std::boxed::Box<
        snarkvm_backend::prelude::Signature<N>,
    >; 14usize]; 2usize],
    pub payload: WeightedSigners<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for RotateSignersInputs<N> {
    fn default() -> Self {
        Self {
            weighted_signers: ::std::default::Default::default(),
            signatures: ::std::array::from_fn(|_| ::std::array::from_fn(|_| ::std::boxed::Box::new(
                snarkvm_backend::prelude::Signature::from((
                    <snarkvm_backend::prelude::Scalar<
                        N,
                    > as snarkvm_backend::prelude::Zero>::zero(),
                    <snarkvm_backend::prelude::Scalar<
                        N,
                    > as snarkvm_backend::prelude::Zero>::zero(),
                    #[allow(clippy::unwrap_used)]
                    snarkvm_backend::prelude::ComputeKey::try_from((
                            <snarkvm_backend::prelude::Group<
                                N,
                            > as snarkvm_backend::prelude::Zero>::zero(),
                            <snarkvm_backend::prelude::Group<
                                N,
                            > as snarkvm_backend::prelude::Zero>::zero(),
                        ))
                        .unwrap(),
                )),
            ))),
            payload: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&RotateSignersInputs<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &RotateSignersInputs<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "weighted_signers".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.weighted_signers)?,
            );
        }
        {
            map.insert(
                "signatures".parse()?,
                {
                    let elements = value
                        .signatures
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> ::anyhow::Result<
                                        snarkvm_backend::prelude::Plaintext<N>,
                                    > {
                                        Ok(
                                            snarkvm_backend::prelude::Plaintext::from(
                                                snarkvm_backend::prelude::Literal::from(**element),
                                            ),
                                        )
                                    })
                                    .collect::<::anyhow::Result<Vec<_>>>()?;
                                snarkvm_backend::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "payload".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.payload)?,
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<RotateSignersInputs<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: RotateSignersInputs<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&RotateSignersInputs<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &RotateSignersInputs<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<RotateSignersInputs<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: RotateSignersInputs<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for RotateSignersInputs<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let weighted_signers = {
            let key: snarkvm_backend::prelude::Identifier<N> = "weighted_signers"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "weighted_signers")
                })?;
            let result: ::anyhow::Result<WeightedSigners<N>> = {
                let member_name = "weighted_signers";
                Ok(
                    WeightedSigners::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(WeightedSigners), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let signatures = {
            let key: snarkvm_backend::prelude::Identifier<N> = "signatures".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "signatures"))?;
            let result: ::anyhow::Result<
                [[::std::boxed::Box<
                    snarkvm_backend::prelude::Signature<N>,
                >; 14usize]; 2usize],
            > = {
                let member_name = "signatures";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<
                            [::std::boxed::Box<
                                snarkvm_backend::prelude::Signature<N>,
                            >; 14usize],
                        > = {
                            let snarkvm_backend::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 14usize {
                                ::anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    14usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: ::anyhow::Result<
                                        ::std::boxed::Box<snarkvm_backend::prelude::Signature<N>>,
                                    > = {
                                        let snarkvm_backend::prelude::Plaintext::Literal(
                                            snarkvm_backend::prelude::Literal::Signature(val),
                                            _,
                                        ) = value else {
                                            ::anyhow::bail!(
                                                "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                                "Signature"
                                            );
                                        };
                                        Ok(val.clone())
                                    };
                                    result
                                })
                                .collect::<::anyhow::Result<Vec<_>>>()?;
                            let arr: [::std::boxed::Box<
                                snarkvm_backend::prelude::Signature<N>,
                            >; 14usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    ::anyhow::anyhow!("Failed to convert Vec to array")
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [[::std::boxed::Box<
                    snarkvm_backend::prelude::Signature<N>,
                >; 14usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let payload = {
            let key: snarkvm_backend::prelude::Identifier<N> = "payload".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "payload"))?;
            let result: ::anyhow::Result<WeightedSigners<N>> = {
                let member_name = "payload";
                Ok(
                    WeightedSigners::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(WeightedSigners), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        Ok(Self {
            weighted_signers,
            signatures,
            payload,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for RotateSignersInputs<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for RotateSignersInputs<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct OutgoingInterchainTransfer<N: snarkvm_backend::prelude::Network> {
    pub its_token_id: [u128; 2usize],
    pub source_address: snarkvm_backend::prelude::Address<N>,
    pub destination_address: [u128; 6usize],
    pub amount: u128,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for OutgoingInterchainTransfer<N> {
    fn default() -> Self {
        Self {
            its_token_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            source_address: snarkvm_backend::prelude::Address::<N>::zero(),
            destination_address: ::std::array::from_fn(|_| ::std::default::Default::default()),
            amount: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&OutgoingInterchainTransfer<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &OutgoingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "its_token_id".parse()?,
                {
                    let elements = value
                        .its_token_id
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "source_address".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.source_address),
                ),
            );
        }
        {
            map.insert(
                "destination_address".parse()?,
                {
                    let elements = value
                        .destination_address
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "amount".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U128(
                        snarkvm_backend::prelude::U128::new(value.amount),
                    ),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<OutgoingInterchainTransfer<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: OutgoingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&OutgoingInterchainTransfer<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &OutgoingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<OutgoingInterchainTransfer<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: OutgoingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for OutgoingInterchainTransfer<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let its_token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "its_token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "its_token_id")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "its_token_id";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let source_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "source_address".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "source_address")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "source_address";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let destination_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_address"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_address")
                })?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "destination_address";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let amount = {
            let key: snarkvm_backend::prelude::Identifier<N> = "amount".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "amount"))?;
            let result: ::anyhow::Result<u128> = {
                let member_name = "amount";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U128(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        Ok(Self {
            its_token_id,
            source_address,
            destination_address,
            amount,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for OutgoingInterchainTransfer<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for OutgoingInterchainTransfer<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Field < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct SendLinkToken<N: snarkvm_backend::prelude::Network> {
    pub token_id: [u128; 2usize],
    pub token_manager_type: u8,
    pub aleo_token_id: snarkvm_backend::prelude::Field<N>,
    pub destination_token_address: [u128; 6usize],
    pub operator: [u128; 6usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default for SendLinkToken<N> {
    fn default() -> Self {
        Self {
            token_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            token_manager_type: ::std::default::Default::default(),
            aleo_token_id: snarkvm_backend::prelude::Field::default(),
            destination_token_address: ::std::array::from_fn(|_| ::std::default::Default::default()),
            operator: ::std::array::from_fn(|_| ::std::default::Default::default()),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&SendLinkToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &SendLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "token_id".parse()?,
                {
                    let elements = value
                        .token_id
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "token_manager_type".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U8(
                        snarkvm_backend::prelude::U8::new(value.token_manager_type),
                    ),
                ),
            );
        }
        {
            map.insert(
                "aleo_token_id".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Field(value.aleo_token_id),
                ),
            );
        }
        {
            map.insert(
                "destination_token_address".parse()?,
                {
                    let elements = value
                        .destination_token_address
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "operator".parse()?,
                {
                    let elements = value
                        .operator
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<SendLinkToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: SendLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&SendLinkToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &SendLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<SendLinkToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: SendLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for SendLinkToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "token_id"))?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "token_id";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let token_manager_type = {
            let key: snarkvm_backend::prelude::Identifier<N> = "token_manager_type"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "token_manager_type")
                })?;
            let result: ::anyhow::Result<u8> = {
                let member_name = "token_manager_type";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U8(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U8"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let aleo_token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "aleo_token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "aleo_token_id")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Field<N>> = {
                let member_name = "aleo_token_id";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Field(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Field"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let destination_token_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_token_address"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_token_address")
                })?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "destination_token_address";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let operator = {
            let key: snarkvm_backend::prelude::Identifier<N> = "operator".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "operator"))?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "operator";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self {
            token_id,
            token_manager_type,
            aleo_token_id,
            destination_token_address,
            operator,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for SendLinkToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for SendLinkToken<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "[[Message < N > ; 24usize] ; 2usize]: for<'a> ::serde::Deserialize<'a>"
)]
pub struct Messages<N: snarkvm_backend::prelude::Network> {
    pub messages: [[Message<N>; 24usize]; 2usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default for Messages<N> {
    fn default() -> Self {
        Self {
            messages: ::std::array::from_fn(|_| ::std::array::from_fn(|_| ::std::default::Default::default())),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&Messages<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &Messages<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "messages".parse()?,
                {
                    let elements = value
                        .messages
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> ::anyhow::Result<
                                        snarkvm_backend::prelude::Plaintext<N>,
                                    > {
                                        snarkvm_backend::prelude::Plaintext::try_from(element)
                                    })
                                    .collect::<::anyhow::Result<Vec<_>>>()?;
                                snarkvm_backend::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<Messages<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: Messages<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&Messages<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &Messages<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<Messages<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: Messages<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for Messages<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let messages = {
            let key: snarkvm_backend::prelude::Identifier<N> = "messages".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "messages"))?;
            let result: ::anyhow::Result<[[Message<N>; 24usize]; 2usize]> = {
                let member_name = "messages";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<[Message<N>; 24usize]> = {
                            let snarkvm_backend::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 24usize {
                                ::anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    24usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: ::anyhow::Result<Message<N>> = {
                                        Ok(
                                            Message::try_from(value)
                                                .map_err(|e| {
                                                    ::anyhow::anyhow!(
                                                        "Failed to convert Plaintext to {}({}): {}",
                                                        stringify!(Message), member_name, e
                                                    )
                                                })?,
                                        )
                                    };
                                    result
                                })
                                .collect::<::anyhow::Result<Vec<_>>>()?;
                            let arr: [Message<N>; 24usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    ::anyhow::anyhow!("Failed to convert Vec to array")
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [[Message<N>; 24usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self { messages })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for Messages<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for Messages<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct MinterProposal<N: snarkvm_backend::prelude::Network> {
    pub proposer: snarkvm_backend::prelude::Address<N>,
    pub token_id: snarkvm_backend::prelude::Field<N>,
    pub new_minter: snarkvm_backend::prelude::Address<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for MinterProposal<N> {
    fn default() -> Self {
        Self {
            proposer: snarkvm_backend::prelude::Address::<N>::zero(),
            token_id: snarkvm_backend::prelude::Field::default(),
            new_minter: snarkvm_backend::prelude::Address::<N>::zero(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&MinterProposal<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &MinterProposal<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "proposer".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.proposer),
                ),
            );
        }
        {
            map.insert(
                "token_id".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Field(value.token_id),
                ),
            );
        }
        {
            map.insert(
                "new_minter".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.new_minter),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<MinterProposal<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: MinterProposal<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&MinterProposal<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &MinterProposal<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<MinterProposal<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: MinterProposal<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for MinterProposal<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let proposer = {
            let key: snarkvm_backend::prelude::Identifier<N> = "proposer".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "proposer"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "proposer";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "token_id"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Field<N>> = {
                let member_name = "token_id";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Field(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Field"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let new_minter = {
            let key: snarkvm_backend::prelude::Identifier<N> = "new_minter".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "new_minter"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "new_minter";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self {
            proposer,
            token_id,
            new_minter,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for MinterProposal<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for MinterProposal<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct Message<N: snarkvm_backend::prelude::Network> {
    pub source_chain: [u128; 2usize],
    pub message_id: [u128; 8usize],
    pub source_address: [u128; 6usize],
    pub contract_address: snarkvm_backend::prelude::Address<N>,
    pub payload_hash: snarkvm_backend::prelude::Group<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default for Message<N> {
    fn default() -> Self {
        Self {
            source_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
            message_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            source_address: ::std::array::from_fn(|_| ::std::default::Default::default()),
            contract_address: snarkvm_backend::prelude::Address::<N>::zero(),
            payload_hash: <snarkvm_backend::prelude::Group<
                N,
            > as snarkvm_backend::prelude::Zero>::zero(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&Message<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &Message<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "source_chain".parse()?,
                {
                    let elements = value
                        .source_chain
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "message_id".parse()?,
                {
                    let elements = value
                        .message_id
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "source_address".parse()?,
                {
                    let elements = value
                        .source_address
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "contract_address".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.contract_address),
                ),
            );
        }
        {
            map.insert(
                "payload_hash".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Group(value.payload_hash),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<Message<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: Message<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&Message<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &Message<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<Message<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: Message<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for Message<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let source_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "source_chain".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "source_chain")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "source_chain";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let message_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "message_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "message_id"))?;
            let result: ::anyhow::Result<[u128; 8usize]> = {
                let member_name = "message_id";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 8usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        8usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 8usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let source_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "source_address".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "source_address")
                })?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "source_address";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let contract_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "contract_address"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "contract_address")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "contract_address";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let payload_hash = {
            let key: snarkvm_backend::prelude::Identifier<N> = "payload_hash".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "payload_hash")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Group<N>> = {
                let member_name = "payload_hash";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Group(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
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
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for Message<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for Message<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct ContractCall<N: snarkvm_backend::prelude::Network> {
    pub caller: snarkvm_backend::prelude::Address<N>,
    pub destination_chain: [u128; 2usize],
    pub destination_address: [u128; 6usize],
    pub payload_hash: snarkvm_backend::prelude::Field<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default for ContractCall<N> {
    fn default() -> Self {
        Self {
            caller: snarkvm_backend::prelude::Address::<N>::zero(),
            destination_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
            destination_address: ::std::array::from_fn(|_| ::std::default::Default::default()),
            payload_hash: snarkvm_backend::prelude::Field::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ContractCall<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &ContractCall<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "caller".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.caller),
                ),
            );
        }
        {
            map.insert(
                "destination_chain".parse()?,
                {
                    let elements = value
                        .destination_chain
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "destination_address".parse()?,
                {
                    let elements = value
                        .destination_address
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "payload_hash".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Field(value.payload_hash),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ContractCall<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ContractCall<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ContractCall<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &ContractCall<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ContractCall<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ContractCall<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for ContractCall<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let caller = {
            let key: snarkvm_backend::prelude::Identifier<N> = "caller".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "caller"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "caller";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let destination_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_chain"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_chain")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "destination_chain";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let destination_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_address"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_address")
                })?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "destination_address";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let payload_hash = {
            let key: snarkvm_backend::prelude::Identifier<N> = "payload_hash".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "payload_hash")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Field<N>> = {
                let member_name = "payload_hash";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Field(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
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
            destination_chain,
            destination_address,
            payload_hash,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for ContractCall<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for ContractCall<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct FromRemoteDeployInterchainToken<N: snarkvm_backend::prelude::Network> {
    pub its_token_id: [u128; 2usize],
    pub name: u128,
    pub symbol: u128,
    pub decimals: u8,
    pub minter: snarkvm_backend::prelude::Address<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for FromRemoteDeployInterchainToken<N> {
    fn default() -> Self {
        Self {
            its_token_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            name: ::std::default::Default::default(),
            symbol: ::std::default::Default::default(),
            decimals: ::std::default::Default::default(),
            minter: snarkvm_backend::prelude::Address::<N>::zero(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&FromRemoteDeployInterchainToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &FromRemoteDeployInterchainToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "its_token_id".parse()?,
                {
                    let elements = value
                        .its_token_id
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "name".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U128(
                        snarkvm_backend::prelude::U128::new(value.name),
                    ),
                ),
            );
        }
        {
            map.insert(
                "symbol".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U128(
                        snarkvm_backend::prelude::U128::new(value.symbol),
                    ),
                ),
            );
        }
        {
            map.insert(
                "decimals".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U8(
                        snarkvm_backend::prelude::U8::new(value.decimals),
                    ),
                ),
            );
        }
        {
            map.insert(
                "minter".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.minter),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<FromRemoteDeployInterchainToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: FromRemoteDeployInterchainToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&FromRemoteDeployInterchainToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &FromRemoteDeployInterchainToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<FromRemoteDeployInterchainToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: FromRemoteDeployInterchainToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>>
for FromRemoteDeployInterchainToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let its_token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "its_token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "its_token_id")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "its_token_id";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let name = {
            let key: snarkvm_backend::prelude::Identifier<N> = "name".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "name"))?;
            let result: ::anyhow::Result<u128> = {
                let member_name = "name";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U128(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let symbol = {
            let key: snarkvm_backend::prelude::Identifier<N> = "symbol".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "symbol"))?;
            let result: ::anyhow::Result<u128> = {
                let member_name = "symbol";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U128(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let decimals = {
            let key: snarkvm_backend::prelude::Identifier<N> = "decimals".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "decimals"))?;
            let result: ::anyhow::Result<u8> = {
                let member_name = "decimals";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U8(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U8"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let minter = {
            let key: snarkvm_backend::prelude::Identifier<N> = "minter".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "minter"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "minter";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self {
            its_token_id,
            name,
            symbol,
            decimals,
            minter,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>>
for FromRemoteDeployInterchainToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for FromRemoteDeployInterchainToken<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
pub struct RemoteDeployInterchainToken {
    pub payload: DeployInterchainToken,
    pub destination_chain: [u128; 2usize],
}
impl ::std::default::Default for RemoteDeployInterchainToken {
    fn default() -> Self {
        Self {
            payload: ::std::default::Default::default(),
            destination_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&RemoteDeployInterchainToken>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &RemoteDeployInterchainToken,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "payload".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.payload)?,
            );
        }
        {
            map.insert(
                "destination_chain".parse()?,
                {
                    let elements = value
                        .destination_chain
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<RemoteDeployInterchainToken>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: RemoteDeployInterchainToken,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&RemoteDeployInterchainToken>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &RemoteDeployInterchainToken,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<RemoteDeployInterchainToken>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: RemoteDeployInterchainToken,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for RemoteDeployInterchainToken {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let payload = {
            let key: snarkvm_backend::prelude::Identifier<N> = "payload".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "payload"))?;
            let result: ::anyhow::Result<DeployInterchainToken> = {
                let member_name = "payload";
                Ok(
                    DeployInterchainToken::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(DeployInterchainToken), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let destination_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_chain"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_chain")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "destination_chain";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self { payload, destination_chain })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for RemoteDeployInterchainToken {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct MinterApproval<N: snarkvm_backend::prelude::Network> {
    pub approver: snarkvm_backend::prelude::Address<N>,
    pub minter: [u128; 6usize],
    pub its_token_id: [u128; 2usize],
    pub destination_chain: snarkvm_backend::prelude::Field<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for MinterApproval<N> {
    fn default() -> Self {
        Self {
            approver: snarkvm_backend::prelude::Address::<N>::zero(),
            minter: ::std::array::from_fn(|_| ::std::default::Default::default()),
            its_token_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            destination_chain: snarkvm_backend::prelude::Field::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&MinterApproval<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &MinterApproval<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "approver".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.approver),
                ),
            );
        }
        {
            map.insert(
                "minter".parse()?,
                {
                    let elements = value
                        .minter
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "its_token_id".parse()?,
                {
                    let elements = value
                        .its_token_id
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "destination_chain".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Field(value.destination_chain),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<MinterApproval<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: MinterApproval<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&MinterApproval<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &MinterApproval<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<MinterApproval<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: MinterApproval<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for MinterApproval<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let approver = {
            let key: snarkvm_backend::prelude::Identifier<N> = "approver".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "approver"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "approver";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let minter = {
            let key: snarkvm_backend::prelude::Identifier<N> = "minter".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "minter"))?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "minter";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let its_token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "its_token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "its_token_id")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "its_token_id";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let destination_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_chain"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_chain")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Field<N>> = {
                let member_name = "destination_chain";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Field(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Field"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self {
            approver,
            minter,
            its_token_id,
            destination_chain,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for MinterApproval<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for MinterApproval<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "IncomingInterchainTransfer < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct ItsIncomingInterchainTransfer<N: snarkvm_backend::prelude::Network> {
    pub inner_message: IncomingInterchainTransfer<N>,
    pub source_chain: [u128; 2usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for ItsIncomingInterchainTransfer<N> {
    fn default() -> Self {
        Self {
            inner_message: ::std::default::Default::default(),
            source_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ItsIncomingInterchainTransfer<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ItsIncomingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "inner_message".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.inner_message)?,
            );
        }
        {
            map.insert(
                "source_chain".parse()?,
                {
                    let elements = value
                        .source_chain
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ItsIncomingInterchainTransfer<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: ItsIncomingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ItsIncomingInterchainTransfer<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ItsIncomingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ItsIncomingInterchainTransfer<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: ItsIncomingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for ItsIncomingInterchainTransfer<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let inner_message = {
            let key: snarkvm_backend::prelude::Identifier<N> = "inner_message".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "inner_message")
                })?;
            let result: ::anyhow::Result<IncomingInterchainTransfer<N>> = {
                let member_name = "inner_message";
                Ok(
                    IncomingInterchainTransfer::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(IncomingInterchainTransfer), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let source_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "source_chain".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "source_chain")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "source_chain";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self {
            inner_message,
            source_chain,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for ItsIncomingInterchainTransfer<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for ItsIncomingInterchainTransfer<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct WeightedSigner<N: snarkvm_backend::prelude::Network> {
    pub addr: snarkvm_backend::prelude::Address<N>,
    pub weight: u128,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for WeightedSigner<N> {
    fn default() -> Self {
        Self {
            addr: snarkvm_backend::prelude::Address::<N>::zero(),
            weight: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&WeightedSigner<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &WeightedSigner<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "addr".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.addr),
                ),
            );
        }
        {
            map.insert(
                "weight".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U128(
                        snarkvm_backend::prelude::U128::new(value.weight),
                    ),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<WeightedSigner<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: WeightedSigner<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&WeightedSigner<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &WeightedSigner<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<WeightedSigner<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: WeightedSigner<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for WeightedSigner<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let addr = {
            let key: snarkvm_backend::prelude::Identifier<N> = "addr".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "addr"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "addr";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let weight = {
            let key: snarkvm_backend::prelude::Identifier<N> = "weight".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "weight"))?;
            let result: ::anyhow::Result<u128> = {
                let member_name = "weight";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U128(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
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
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for WeightedSigner<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for WeightedSigner<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "SendLinkToken < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct WrappedSendLinkToken<N: snarkvm_backend::prelude::Network> {
    pub link_token: SendLinkToken<N>,
    pub destination_chain: [u128; 2usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for WrappedSendLinkToken<N> {
    fn default() -> Self {
        Self {
            link_token: ::std::default::Default::default(),
            destination_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&WrappedSendLinkToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &WrappedSendLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "link_token".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.link_token)?,
            );
        }
        {
            map.insert(
                "destination_chain".parse()?,
                {
                    let elements = value
                        .destination_chain
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<WrappedSendLinkToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: WrappedSendLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&WrappedSendLinkToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &WrappedSendLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<WrappedSendLinkToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: WrappedSendLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for WrappedSendLinkToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let link_token = {
            let key: snarkvm_backend::prelude::Identifier<N> = "link_token".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "link_token"))?;
            let result: ::anyhow::Result<SendLinkToken<N>> = {
                let member_name = "link_token";
                Ok(
                    SendLinkToken::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(SendLinkToken), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let destination_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_chain"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_chain")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "destination_chain";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self {
            link_token,
            destination_chain,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for WrappedSendLinkToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for WrappedSendLinkToken<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct IncomingInterchainTransfer<N: snarkvm_backend::prelude::Network> {
    pub its_token_id: [u128; 2usize],
    pub source_address: [u128; 6usize],
    pub destination_address: snarkvm_backend::prelude::Address<N>,
    pub amount: u128,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for IncomingInterchainTransfer<N> {
    fn default() -> Self {
        Self {
            its_token_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            source_address: ::std::array::from_fn(|_| ::std::default::Default::default()),
            destination_address: snarkvm_backend::prelude::Address::<N>::zero(),
            amount: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&IncomingInterchainTransfer<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &IncomingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "its_token_id".parse()?,
                {
                    let elements = value
                        .its_token_id
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "source_address".parse()?,
                {
                    let elements = value
                        .source_address
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "destination_address".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.destination_address),
                ),
            );
        }
        {
            map.insert(
                "amount".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U128(
                        snarkvm_backend::prelude::U128::new(value.amount),
                    ),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<IncomingInterchainTransfer<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: IncomingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&IncomingInterchainTransfer<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &IncomingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<IncomingInterchainTransfer<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: IncomingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for IncomingInterchainTransfer<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let its_token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "its_token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "its_token_id")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "its_token_id";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let source_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "source_address".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "source_address")
                })?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "source_address";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let destination_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_address"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_address")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "destination_address";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let amount = {
            let key: snarkvm_backend::prelude::Identifier<N> = "amount".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "amount"))?;
            let result: ::anyhow::Result<u128> = {
                let member_name = "amount";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U128(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        Ok(Self {
            its_token_id,
            source_address,
            destination_address,
            amount,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for IncomingInterchainTransfer<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for IncomingInterchainTransfer<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "WeightedSigners < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct ApproveMessagesInputs<N: snarkvm_backend::prelude::Network> {
    pub weighted_signers: WeightedSigners<N>,
    pub signatures: [[::std::boxed::Box<
        snarkvm_backend::prelude::Signature<N>,
    >; 14usize]; 2usize],
    pub messages: [[snarkvm_backend::prelude::Group<N>; 24usize]; 2usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for ApproveMessagesInputs<N> {
    fn default() -> Self {
        Self {
            weighted_signers: ::std::default::Default::default(),
            signatures: ::std::array::from_fn(|_| ::std::array::from_fn(|_| ::std::boxed::Box::new(
                snarkvm_backend::prelude::Signature::from((
                    <snarkvm_backend::prelude::Scalar<
                        N,
                    > as snarkvm_backend::prelude::Zero>::zero(),
                    <snarkvm_backend::prelude::Scalar<
                        N,
                    > as snarkvm_backend::prelude::Zero>::zero(),
                    #[allow(clippy::unwrap_used)]
                    snarkvm_backend::prelude::ComputeKey::try_from((
                            <snarkvm_backend::prelude::Group<
                                N,
                            > as snarkvm_backend::prelude::Zero>::zero(),
                            <snarkvm_backend::prelude::Group<
                                N,
                            > as snarkvm_backend::prelude::Zero>::zero(),
                        ))
                        .unwrap(),
                )),
            ))),
            messages: ::std::array::from_fn(|_| ::std::array::from_fn(|_| <snarkvm_backend::prelude::Group<
                N,
            > as snarkvm_backend::prelude::Zero>::zero())),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ApproveMessagesInputs<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ApproveMessagesInputs<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "weighted_signers".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.weighted_signers)?,
            );
        }
        {
            map.insert(
                "signatures".parse()?,
                {
                    let elements = value
                        .signatures
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> ::anyhow::Result<
                                        snarkvm_backend::prelude::Plaintext<N>,
                                    > {
                                        Ok(
                                            snarkvm_backend::prelude::Plaintext::from(
                                                snarkvm_backend::prelude::Literal::from(**element),
                                            ),
                                        )
                                    })
                                    .collect::<::anyhow::Result<Vec<_>>>()?;
                                snarkvm_backend::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "messages".parse()?,
                {
                    let elements = value
                        .messages
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> ::anyhow::Result<
                                        snarkvm_backend::prelude::Plaintext<N>,
                                    > {
                                        Ok(
                                            snarkvm_backend::prelude::Plaintext::from(
                                                snarkvm_backend::prelude::Literal::Group(*element),
                                            ),
                                        )
                                    })
                                    .collect::<::anyhow::Result<Vec<_>>>()?;
                                snarkvm_backend::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ApproveMessagesInputs<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ApproveMessagesInputs<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ApproveMessagesInputs<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ApproveMessagesInputs<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ApproveMessagesInputs<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ApproveMessagesInputs<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for ApproveMessagesInputs<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let weighted_signers = {
            let key: snarkvm_backend::prelude::Identifier<N> = "weighted_signers"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "weighted_signers")
                })?;
            let result: ::anyhow::Result<WeightedSigners<N>> = {
                let member_name = "weighted_signers";
                Ok(
                    WeightedSigners::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(WeightedSigners), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let signatures = {
            let key: snarkvm_backend::prelude::Identifier<N> = "signatures".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "signatures"))?;
            let result: ::anyhow::Result<
                [[::std::boxed::Box<
                    snarkvm_backend::prelude::Signature<N>,
                >; 14usize]; 2usize],
            > = {
                let member_name = "signatures";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<
                            [::std::boxed::Box<
                                snarkvm_backend::prelude::Signature<N>,
                            >; 14usize],
                        > = {
                            let snarkvm_backend::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 14usize {
                                ::anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    14usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: ::anyhow::Result<
                                        ::std::boxed::Box<snarkvm_backend::prelude::Signature<N>>,
                                    > = {
                                        let snarkvm_backend::prelude::Plaintext::Literal(
                                            snarkvm_backend::prelude::Literal::Signature(val),
                                            _,
                                        ) = value else {
                                            ::anyhow::bail!(
                                                "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                                "Signature"
                                            );
                                        };
                                        Ok(val.clone())
                                    };
                                    result
                                })
                                .collect::<::anyhow::Result<Vec<_>>>()?;
                            let arr: [::std::boxed::Box<
                                snarkvm_backend::prelude::Signature<N>,
                            >; 14usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    ::anyhow::anyhow!("Failed to convert Vec to array")
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [[::std::boxed::Box<
                    snarkvm_backend::prelude::Signature<N>,
                >; 14usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let messages = {
            let key: snarkvm_backend::prelude::Identifier<N> = "messages".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "messages"))?;
            let result: ::anyhow::Result<
                [[snarkvm_backend::prelude::Group<N>; 24usize]; 2usize],
            > = {
                let member_name = "messages";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<
                            [snarkvm_backend::prelude::Group<N>; 24usize],
                        > = {
                            let snarkvm_backend::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 24usize {
                                ::anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    24usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: ::anyhow::Result<
                                        snarkvm_backend::prelude::Group<N>,
                                    > = {
                                        let snarkvm_backend::prelude::Plaintext::Literal(
                                            snarkvm_backend::prelude::Literal::Group(val),
                                            _,
                                        ) = value else {
                                            ::anyhow::bail!(
                                                "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                                "Group"
                                            );
                                        };
                                        Ok(*val)
                                    };
                                    result
                                })
                                .collect::<::anyhow::Result<Vec<_>>>()?;
                            let arr: [snarkvm_backend::prelude::Group<N>; 24usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    ::anyhow::anyhow!("Failed to convert Vec to array")
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [[snarkvm_backend::prelude::Group<N>; 24usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self {
            weighted_signers,
            signatures,
            messages,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for ApproveMessagesInputs<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for ApproveMessagesInputs<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "WeightedSigners < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct PayloadDigest<N: snarkvm_backend::prelude::Network> {
    pub domain_separator: [u128; 2usize],
    pub signer: WeightedSigners<N>,
    pub data_hash: snarkvm_backend::prelude::Group<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default for PayloadDigest<N> {
    fn default() -> Self {
        Self {
            domain_separator: ::std::array::from_fn(|_| ::std::default::Default::default()),
            signer: ::std::default::Default::default(),
            data_hash: <snarkvm_backend::prelude::Group<
                N,
            > as snarkvm_backend::prelude::Zero>::zero(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&PayloadDigest<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &PayloadDigest<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "domain_separator".parse()?,
                {
                    let elements = value
                        .domain_separator
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "signer".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.signer)?,
            );
        }
        {
            map.insert(
                "data_hash".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Group(value.data_hash),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<PayloadDigest<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: PayloadDigest<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&PayloadDigest<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &PayloadDigest<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<PayloadDigest<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: PayloadDigest<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for PayloadDigest<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let domain_separator = {
            let key: snarkvm_backend::prelude::Identifier<N> = "domain_separator"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "domain_separator")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "domain_separator";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let signer = {
            let key: snarkvm_backend::prelude::Identifier<N> = "signer".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "signer"))?;
            let result: ::anyhow::Result<WeightedSigners<N>> = {
                let member_name = "signer";
                Ok(
                    WeightedSigners::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(WeightedSigners), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let data_hash = {
            let key: snarkvm_backend::prelude::Identifier<N> = "data_hash".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "data_hash"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Group<N>> = {
                let member_name = "data_hash";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Group(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
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
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for PayloadDigest<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for PayloadDigest<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "[[WeightedSigner < N > ; 14usize] ; 2usize]: for<'a> ::serde::Deserialize<'a>"
)]
pub struct WeightedSigners<N: snarkvm_backend::prelude::Network> {
    pub signers: [[WeightedSigner<N>; 14usize]; 2usize],
    pub quorum: u128,
    pub nonce: u64,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for WeightedSigners<N> {
    fn default() -> Self {
        Self {
            signers: ::std::array::from_fn(|_| ::std::array::from_fn(|_| ::std::default::Default::default())),
            quorum: ::std::default::Default::default(),
            nonce: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&WeightedSigners<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &WeightedSigners<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "signers".parse()?,
                {
                    let elements = value
                        .signers
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> ::anyhow::Result<
                                        snarkvm_backend::prelude::Plaintext<N>,
                                    > {
                                        snarkvm_backend::prelude::Plaintext::try_from(element)
                                    })
                                    .collect::<::anyhow::Result<Vec<_>>>()?;
                                snarkvm_backend::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "quorum".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U128(
                        snarkvm_backend::prelude::U128::new(value.quorum),
                    ),
                ),
            );
        }
        {
            map.insert(
                "nonce".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U64(
                        snarkvm_backend::prelude::U64::new(value.nonce),
                    ),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<WeightedSigners<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: WeightedSigners<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&WeightedSigners<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &WeightedSigners<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<WeightedSigners<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: WeightedSigners<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for WeightedSigners<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let signers = {
            let key: snarkvm_backend::prelude::Identifier<N> = "signers".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "signers"))?;
            let result: ::anyhow::Result<[[WeightedSigner<N>; 14usize]; 2usize]> = {
                let member_name = "signers";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<[WeightedSigner<N>; 14usize]> = {
                            let snarkvm_backend::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 14usize {
                                ::anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    14usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: ::anyhow::Result<WeightedSigner<N>> = {
                                        Ok(
                                            WeightedSigner::try_from(value)
                                                .map_err(|e| {
                                                    ::anyhow::anyhow!(
                                                        "Failed to convert Plaintext to {}({}): {}",
                                                        stringify!(WeightedSigner), member_name, e
                                                    )
                                                })?,
                                        )
                                    };
                                    result
                                })
                                .collect::<::anyhow::Result<Vec<_>>>()?;
                            let arr: [WeightedSigner<N>; 14usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    ::anyhow::anyhow!("Failed to convert Vec to array")
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [[WeightedSigner<N>; 14usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let quorum = {
            let key: snarkvm_backend::prelude::Identifier<N> = "quorum".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "quorum"))?;
            let result: ::anyhow::Result<u128> = {
                let member_name = "quorum";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U128(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let nonce = {
            let key: snarkvm_backend::prelude::Identifier<N> = "nonce".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "nonce"))?;
            let result: ::anyhow::Result<u64> = {
                let member_name = "nonce";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U64(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U64"
                    );
                };
                Ok(**val)
            };
            result?
        };
        Ok(Self { signers, quorum, nonce })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for WeightedSigners<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for WeightedSigners<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Group < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct ValidateMessageInputs<N: snarkvm_backend::prelude::Network> {
    pub message_hash: snarkvm_backend::prelude::Group<N>,
    pub message_batch_hash: snarkvm_backend::prelude::Group<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for ValidateMessageInputs<N> {
    fn default() -> Self {
        Self {
            message_hash: <snarkvm_backend::prelude::Group<
                N,
            > as snarkvm_backend::prelude::Zero>::zero(),
            message_batch_hash: <snarkvm_backend::prelude::Group<
                N,
            > as snarkvm_backend::prelude::Zero>::zero(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ValidateMessageInputs<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ValidateMessageInputs<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "message_hash".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Group(value.message_hash),
                ),
            );
        }
        {
            map.insert(
                "message_batch_hash".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Group(value.message_batch_hash),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ValidateMessageInputs<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ValidateMessageInputs<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ValidateMessageInputs<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ValidateMessageInputs<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ValidateMessageInputs<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ValidateMessageInputs<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for ValidateMessageInputs<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let message_hash = {
            let key: snarkvm_backend::prelude::Identifier<N> = "message_hash".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "message_hash")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Group<N>> = {
                let member_name = "message_hash";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Group(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Group"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let message_batch_hash = {
            let key: snarkvm_backend::prelude::Identifier<N> = "message_batch_hash"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "message_batch_hash")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Group<N>> = {
                let member_name = "message_batch_hash";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Group(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Group"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self {
            message_hash,
            message_batch_hash,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for ValidateMessageInputs<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for ValidateMessageInputs<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Group < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct SignersRotated<N: snarkvm_backend::prelude::Network> {
    pub new_signers_hash: snarkvm_backend::prelude::Group<N>,
    pub new_signers_data: WeightedSigners<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for SignersRotated<N> {
    fn default() -> Self {
        Self {
            new_signers_hash: <snarkvm_backend::prelude::Group<
                N,
            > as snarkvm_backend::prelude::Zero>::zero(),
            new_signers_data: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&SignersRotated<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &SignersRotated<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "new_signers_hash".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Group(value.new_signers_hash),
                ),
            );
        }
        {
            map.insert(
                "new_signers_data".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.new_signers_data)?,
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<SignersRotated<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: SignersRotated<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&SignersRotated<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &SignersRotated<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<SignersRotated<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: SignersRotated<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for SignersRotated<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let new_signers_hash = {
            let key: snarkvm_backend::prelude::Identifier<N> = "new_signers_hash"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "new_signers_hash")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Group<N>> = {
                let member_name = "new_signers_hash";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Group(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Group"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let new_signers_data = {
            let key: snarkvm_backend::prelude::Identifier<N> = "new_signers_data"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "new_signers_data")
                })?;
            let result: ::anyhow::Result<WeightedSigners<N>> = {
                let member_name = "new_signers_data";
                Ok(
                    WeightedSigners::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(WeightedSigners), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        Ok(Self {
            new_signers_hash,
            new_signers_data,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for SignersRotated<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for SignersRotated<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "Proof < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct ExecuteData<N: snarkvm_backend::prelude::Network> {
    pub proof: Proof<N>,
    pub message: Messages<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default for ExecuteData<N> {
    fn default() -> Self {
        Self {
            proof: ::std::default::Default::default(),
            message: ::std::default::Default::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ExecuteData<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &ExecuteData<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "proof".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.proof)?,
            );
        }
        {
            map.insert(
                "message".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.message)?,
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ExecuteData<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ExecuteData<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ExecuteData<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &ExecuteData<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ExecuteData<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ExecuteData<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for ExecuteData<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let proof = {
            let key: snarkvm_backend::prelude::Identifier<N> = "proof".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "proof"))?;
            let result: ::anyhow::Result<Proof<N>> = {
                let member_name = "proof";
                Ok(
                    Proof::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(Proof), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let message = {
            let key: snarkvm_backend::prelude::Identifier<N> = "message".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "message"))?;
            let result: ::anyhow::Result<Messages<N>> = {
                let member_name = "message";
                Ok(
                    Messages::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(Messages), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        Ok(Self { proof, message })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for ExecuteData<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for ExecuteData<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
pub struct DeployInterchainToken {
    pub its_token_id: [u128; 2usize],
    pub name: u128,
    pub symbol: u128,
    pub decimals: u8,
    pub minter: [u128; 6usize],
}
impl ::std::default::Default for DeployInterchainToken {
    fn default() -> Self {
        Self {
            its_token_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            name: ::std::default::Default::default(),
            symbol: ::std::default::Default::default(),
            decimals: ::std::default::Default::default(),
            minter: ::std::array::from_fn(|_| ::std::default::Default::default()),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&DeployInterchainToken>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &DeployInterchainToken) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "its_token_id".parse()?,
                {
                    let elements = value
                        .its_token_id
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "name".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U128(
                        snarkvm_backend::prelude::U128::new(value.name),
                    ),
                ),
            );
        }
        {
            map.insert(
                "symbol".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U128(
                        snarkvm_backend::prelude::U128::new(value.symbol),
                    ),
                ),
            );
        }
        {
            map.insert(
                "decimals".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U8(
                        snarkvm_backend::prelude::U8::new(value.decimals),
                    ),
                ),
            );
        }
        {
            map.insert(
                "minter".parse()?,
                {
                    let elements = value
                        .minter
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<DeployInterchainToken>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: DeployInterchainToken) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&DeployInterchainToken>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &DeployInterchainToken) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<DeployInterchainToken>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: DeployInterchainToken) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for DeployInterchainToken {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let its_token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "its_token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "its_token_id")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "its_token_id";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let name = {
            let key: snarkvm_backend::prelude::Identifier<N> = "name".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "name"))?;
            let result: ::anyhow::Result<u128> = {
                let member_name = "name";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U128(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let symbol = {
            let key: snarkvm_backend::prelude::Identifier<N> = "symbol".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "symbol"))?;
            let result: ::anyhow::Result<u128> = {
                let member_name = "symbol";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U128(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U128"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let decimals = {
            let key: snarkvm_backend::prelude::Identifier<N> = "decimals".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "decimals"))?;
            let result: ::anyhow::Result<u8> = {
                let member_name = "decimals";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U8(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U8"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let minter = {
            let key: snarkvm_backend::prelude::Identifier<N> = "minter".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "minter"))?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "minter";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self {
            its_token_id,
            name,
            symbol,
            decimals,
            minter,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for DeployInterchainToken {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "WeightedSigners < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct Proof<N: snarkvm_backend::prelude::Network> {
    pub weighted_signers: WeightedSigners<N>,
    pub signatures: [[::std::boxed::Box<
        snarkvm_backend::prelude::Signature<N>,
    >; 14usize]; 2usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default for Proof<N> {
    fn default() -> Self {
        Self {
            weighted_signers: ::std::default::Default::default(),
            signatures: ::std::array::from_fn(|_| ::std::array::from_fn(|_| ::std::boxed::Box::new(
                snarkvm_backend::prelude::Signature::from((
                    <snarkvm_backend::prelude::Scalar<
                        N,
                    > as snarkvm_backend::prelude::Zero>::zero(),
                    <snarkvm_backend::prelude::Scalar<
                        N,
                    > as snarkvm_backend::prelude::Zero>::zero(),
                    #[allow(clippy::unwrap_used)]
                    snarkvm_backend::prelude::ComputeKey::try_from((
                            <snarkvm_backend::prelude::Group<
                                N,
                            > as snarkvm_backend::prelude::Zero>::zero(),
                            <snarkvm_backend::prelude::Group<
                                N,
                            > as snarkvm_backend::prelude::Zero>::zero(),
                        ))
                        .unwrap(),
                )),
            ))),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&Proof<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &Proof<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "weighted_signers".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.weighted_signers)?,
            );
        }
        {
            map.insert(
                "signatures".parse()?,
                {
                    let elements = value
                        .signatures
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok({
                                let elements = element
                                    .iter()
                                    .map(|
                                        element,
                                    | -> ::anyhow::Result<
                                        snarkvm_backend::prelude::Plaintext<N>,
                                    > {
                                        Ok(
                                            snarkvm_backend::prelude::Plaintext::from(
                                                snarkvm_backend::prelude::Literal::from(**element),
                                            ),
                                        )
                                    })
                                    .collect::<::anyhow::Result<Vec<_>>>()?;
                                snarkvm_backend::prelude::Plaintext::Array(
                                    elements,
                                    ::std::default::Default::default(),
                                )
                            })
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<Proof<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: Proof<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&Proof<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &Proof<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<Proof<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: Proof<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for Proof<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let weighted_signers = {
            let key: snarkvm_backend::prelude::Identifier<N> = "weighted_signers"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "weighted_signers")
                })?;
            let result: ::anyhow::Result<WeightedSigners<N>> = {
                let member_name = "weighted_signers";
                Ok(
                    WeightedSigners::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(WeightedSigners), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let signatures = {
            let key: snarkvm_backend::prelude::Identifier<N> = "signatures".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "signatures"))?;
            let result: ::anyhow::Result<
                [[::std::boxed::Box<
                    snarkvm_backend::prelude::Signature<N>,
                >; 14usize]; 2usize],
            > = {
                let member_name = "signatures";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<
                            [::std::boxed::Box<
                                snarkvm_backend::prelude::Signature<N>,
                            >; 14usize],
                        > = {
                            let snarkvm_backend::prelude::Plaintext::Array(
                                elements,
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Array for member '{member_name}'"
                                );
                            };
                            if elements.len() != 14usize {
                                ::anyhow::bail!(
                                    "Array length mismatch for member '{member_name}': expected {}, got {}",
                                    14usize, elements.len()
                                );
                            }
                            let converted_elements = elements
                                .iter()
                                .map(|element| {
                                    let value = element;
                                    let result: ::anyhow::Result<
                                        ::std::boxed::Box<snarkvm_backend::prelude::Signature<N>>,
                                    > = {
                                        let snarkvm_backend::prelude::Plaintext::Literal(
                                            snarkvm_backend::prelude::Literal::Signature(val),
                                            _,
                                        ) = value else {
                                            ::anyhow::bail!(
                                                "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                                "Signature"
                                            );
                                        };
                                        Ok(val.clone())
                                    };
                                    result
                                })
                                .collect::<::anyhow::Result<Vec<_>>>()?;
                            let arr: [::std::boxed::Box<
                                snarkvm_backend::prelude::Signature<N>,
                            >; 14usize] = converted_elements
                                .try_into()
                                .map_err(|_| {
                                    ::anyhow::anyhow!("Failed to convert Vec to array")
                                })?;
                            Ok(arr)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [[::std::boxed::Box<
                    snarkvm_backend::prelude::Signature<N>,
                >; 14usize]; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
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
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for Proof<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for Proof<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Address < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct TokenOwner<N: snarkvm_backend::prelude::Network> {
    pub account: snarkvm_backend::prelude::Address<N>,
    pub token_id: snarkvm_backend::prelude::Field<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default for TokenOwner<N> {
    fn default() -> Self {
        Self {
            account: snarkvm_backend::prelude::Address::<N>::zero(),
            token_id: snarkvm_backend::prelude::Field::default(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&TokenOwner<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &TokenOwner<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "account".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.account),
                ),
            );
        }
        {
            map.insert(
                "token_id".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Field(value.token_id),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<TokenOwner<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: TokenOwner<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&TokenOwner<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &TokenOwner<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<TokenOwner<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: TokenOwner<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for TokenOwner<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let account = {
            let key: snarkvm_backend::prelude::Identifier<N> = "account".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "account"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "account";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "token_id"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Field<N>> = {
                let member_name = "token_id";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Field(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Field"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self { account, token_id })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for TokenOwner<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for TokenOwner<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "ReceivedLinkToken < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct WrappedReceivedLinkToken<N: snarkvm_backend::prelude::Network> {
    pub link_token: ReceivedLinkToken<N>,
    pub source_chain: [u128; 2usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for WrappedReceivedLinkToken<N> {
    fn default() -> Self {
        Self {
            link_token: ::std::default::Default::default(),
            source_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&WrappedReceivedLinkToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &WrappedReceivedLinkToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "link_token".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.link_token)?,
            );
        }
        {
            map.insert(
                "source_chain".parse()?,
                {
                    let elements = value
                        .source_chain
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<WrappedReceivedLinkToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: WrappedReceivedLinkToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&WrappedReceivedLinkToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &WrappedReceivedLinkToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<WrappedReceivedLinkToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: WrappedReceivedLinkToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for WrappedReceivedLinkToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let link_token = {
            let key: snarkvm_backend::prelude::Identifier<N> = "link_token".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "link_token"))?;
            let result: ::anyhow::Result<ReceivedLinkToken<N>> = {
                let member_name = "link_token";
                Ok(
                    ReceivedLinkToken::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(ReceivedLinkToken), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let source_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "source_chain".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "source_chain")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "source_chain";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self { link_token, source_chain })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for WrappedReceivedLinkToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for WrappedReceivedLinkToken<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(bound = "OutgoingInterchainTransfer < N >: for<'a> ::serde::Deserialize<'a>")]
pub struct ItsOutgoingInterchainTransfer<N: snarkvm_backend::prelude::Network> {
    pub inner_message: OutgoingInterchainTransfer<N>,
    pub destination_chain: [u128; 2usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for ItsOutgoingInterchainTransfer<N> {
    fn default() -> Self {
        Self {
            inner_message: ::std::default::Default::default(),
            destination_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ItsOutgoingInterchainTransfer<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ItsOutgoingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "inner_message".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.inner_message)?,
            );
        }
        {
            map.insert(
                "destination_chain".parse()?,
                {
                    let elements = value
                        .destination_chain
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ItsOutgoingInterchainTransfer<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: ItsOutgoingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ItsOutgoingInterchainTransfer<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ItsOutgoingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ItsOutgoingInterchainTransfer<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: ItsOutgoingInterchainTransfer<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for ItsOutgoingInterchainTransfer<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let inner_message = {
            let key: snarkvm_backend::prelude::Identifier<N> = "inner_message".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "inner_message")
                })?;
            let result: ::anyhow::Result<OutgoingInterchainTransfer<N>> = {
                let member_name = "inner_message";
                Ok(
                    OutgoingInterchainTransfer::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(OutgoingInterchainTransfer), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let destination_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_chain"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_chain")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "destination_chain";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self {
            inner_message,
            destination_chain,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for ItsOutgoingInterchainTransfer<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for ItsOutgoingInterchainTransfer<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "snarkvm_backend :: prelude :: Field < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct ReceivedLinkToken<N: snarkvm_backend::prelude::Network> {
    pub its_token_id: [u128; 2usize],
    pub token_manager_type: u8,
    pub source_token_address: [u128; 6usize],
    pub destination_token_address: snarkvm_backend::prelude::Field<N>,
    pub operator: snarkvm_backend::prelude::Address<N>,
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for ReceivedLinkToken<N> {
    fn default() -> Self {
        Self {
            its_token_id: ::std::array::from_fn(|_| ::std::default::Default::default()),
            token_manager_type: ::std::default::Default::default(),
            source_token_address: ::std::array::from_fn(|_| ::std::default::Default::default()),
            destination_token_address: snarkvm_backend::prelude::Field::default(),
            operator: snarkvm_backend::prelude::Address::<N>::zero(),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ReceivedLinkToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &ReceivedLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "its_token_id".parse()?,
                {
                    let elements = value
                        .its_token_id
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "token_manager_type".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::U8(
                        snarkvm_backend::prelude::U8::new(value.token_manager_type),
                    ),
                ),
            );
        }
        {
            map.insert(
                "source_token_address".parse()?,
                {
                    let elements = value
                        .source_token_address
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        {
            map.insert(
                "destination_token_address".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Field(
                        value.destination_token_address,
                    ),
                ),
            );
        }
        {
            map.insert(
                "operator".parse()?,
                snarkvm_backend::prelude::Plaintext::from(
                    snarkvm_backend::prelude::Literal::Address(value.operator),
                ),
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ReceivedLinkToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ReceivedLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ReceivedLinkToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: &ReceivedLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ReceivedLinkToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(value: ReceivedLinkToken<N>) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>> for ReceivedLinkToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let its_token_id = {
            let key: snarkvm_backend::prelude::Identifier<N> = "its_token_id".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "its_token_id")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "its_token_id";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let token_manager_type = {
            let key: snarkvm_backend::prelude::Identifier<N> = "token_manager_type"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "token_manager_type")
                })?;
            let result: ::anyhow::Result<u8> = {
                let member_name = "token_manager_type";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::U8(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "U8"
                    );
                };
                Ok(**val)
            };
            result?
        };
        let source_token_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "source_token_address"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "source_token_address")
                })?;
            let result: ::anyhow::Result<[u128; 6usize]> = {
                let member_name = "source_token_address";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 6usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        6usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 6usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        let destination_token_address = {
            let key: snarkvm_backend::prelude::Identifier<N> = "destination_token_address"
                .parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "destination_token_address")
                })?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Field<N>> = {
                let member_name = "destination_token_address";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Field(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Field"
                    );
                };
                Ok(*val)
            };
            result?
        };
        let operator = {
            let key: snarkvm_backend::prelude::Identifier<N> = "operator".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| ::anyhow::anyhow!("Missing member '{}'", "operator"))?;
            let result: ::anyhow::Result<snarkvm_backend::prelude::Address<N>> = {
                let member_name = "operator";
                let snarkvm_backend::prelude::Plaintext::Literal(
                    snarkvm_backend::prelude::Literal::Address(val),
                    _,
                ) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Literal({}) for member '{member_name}'",
                        "Address"
                    );
                };
                Ok(*val)
            };
            result?
        };
        Ok(Self {
            its_token_id,
            token_manager_type,
            source_token_address,
            destination_token_address,
            operator,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>> for ReceivedLinkToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr for ReceivedLinkToken<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize, ::serde::Serialize)]
#[serde(
    bound = "FromRemoteDeployInterchainToken < N >: for<'a> ::serde::Deserialize<'a>"
)]
pub struct ItsMessageDeployInterchainToken<N: snarkvm_backend::prelude::Network> {
    pub inner_message: FromRemoteDeployInterchainToken<N>,
    pub source_chain: [u128; 2usize],
}
impl<N: snarkvm_backend::prelude::Network> ::std::default::Default
for ItsMessageDeployInterchainToken<N> {
    fn default() -> Self {
        Self {
            inner_message: ::std::default::Default::default(),
            source_chain: ::std::array::from_fn(|_| ::std::default::Default::default()),
        }
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ItsMessageDeployInterchainToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ItsMessageDeployInterchainToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let mut map = ::indexmap::IndexMap::new();
        {
            map.insert(
                "inner_message".parse()?,
                snarkvm_backend::prelude::Plaintext::try_from(&value.inner_message)?,
            );
        }
        {
            map.insert(
                "source_chain".parse()?,
                {
                    let elements = value
                        .source_chain
                        .iter()
                        .map(|
                            element,
                        | -> ::anyhow::Result<snarkvm_backend::prelude::Plaintext<N>> {
                            Ok(
                                snarkvm_backend::prelude::Plaintext::from(
                                    snarkvm_backend::prelude::Literal::U128(
                                        snarkvm_backend::prelude::U128::new(*element),
                                    ),
                                ),
                            )
                        })
                        .collect::<::anyhow::Result<Vec<_>>>()?;
                    snarkvm_backend::prelude::Plaintext::Array(
                        elements,
                        ::std::default::Default::default(),
                    )
                },
            );
        }
        let plaintext = snarkvm_backend::prelude::Plaintext::Struct(
            map,
            ::std::sync::OnceLock::new(),
        );
        Ok(plaintext)
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ItsMessageDeployInterchainToken<N>>
for snarkvm_backend::prelude::Plaintext<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: ItsMessageDeployInterchainToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<&ItsMessageDeployInterchainToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &ItsMessageDeployInterchainToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = value.try_into()?;
        Ok(snarkvm_backend::prelude::Value::Plaintext(plaintext))
    }
}
impl<N: snarkvm_backend::prelude::Network> TryFrom<ItsMessageDeployInterchainToken<N>>
for snarkvm_backend::prelude::Value<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: ItsMessageDeployInterchainToken<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<&snarkvm_backend::prelude::Plaintext<N>>
for ItsMessageDeployInterchainToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: &snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        let snarkvm_backend::prelude::Plaintext::Struct(map, _) = value else {
            ::anyhow::bail!("Expected a Plaintext::Struct. Input value: {:?}", value);
        };
        let inner_message = {
            let key: snarkvm_backend::prelude::Identifier<N> = "inner_message".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "inner_message")
                })?;
            let result: ::anyhow::Result<FromRemoteDeployInterchainToken<N>> = {
                let member_name = "inner_message";
                Ok(
                    FromRemoteDeployInterchainToken::try_from(value)
                        .map_err(|e| {
                            ::anyhow::anyhow!(
                                "Failed to convert Plaintext to {}({}): {}",
                                stringify!(FromRemoteDeployInterchainToken), member_name, e
                            )
                        })?,
                )
            };
            result?
        };
        let source_chain = {
            let key: snarkvm_backend::prelude::Identifier<N> = "source_chain".parse()?;
            let value = map
                .get(&key)
                .ok_or_else(|| {
                    ::anyhow::anyhow!("Missing member '{}'", "source_chain")
                })?;
            let result: ::anyhow::Result<[u128; 2usize]> = {
                let member_name = "source_chain";
                let snarkvm_backend::prelude::Plaintext::Array(elements, _) = value else {
                    ::anyhow::bail!(
                        "Expected a Plaintext::Array for member '{member_name}'"
                    );
                };
                if elements.len() != 2usize {
                    ::anyhow::bail!(
                        "Array length mismatch for member '{member_name}': expected {}, got {}",
                        2usize, elements.len()
                    );
                }
                let converted_elements = elements
                    .iter()
                    .map(|element| {
                        let value = element;
                        let result: ::anyhow::Result<u128> = {
                            let snarkvm_backend::prelude::Plaintext::Literal(
                                snarkvm_backend::prelude::Literal::U128(val),
                                _,
                            ) = value else {
                                ::anyhow::bail!(
                                    "Expected a Plaintext::Literal({}) for member '{member_name}'",
                                    "U128"
                                );
                            };
                            Ok(**val)
                        };
                        result
                    })
                    .collect::<::anyhow::Result<Vec<_>>>()?;
                let arr: [u128; 2usize] = converted_elements
                    .try_into()
                    .map_err(|_| ::anyhow::anyhow!("Failed to convert Vec to array"))?;
                Ok(arr)
            };
            result?
        };
        Ok(Self {
            inner_message,
            source_chain,
        })
    }
}
impl<
    N: snarkvm_backend::prelude::Network,
> TryFrom<snarkvm_backend::prelude::Plaintext<N>>
for ItsMessageDeployInterchainToken<N> {
    type Error = ::anyhow::Error;
    fn try_from(
        value: snarkvm_backend::prelude::Plaintext<N>,
    ) -> ::anyhow::Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl<N: snarkvm_backend::prelude::Network> ::std::str::FromStr
for ItsMessageDeployInterchainToken<N> {
    type Err = ::anyhow::Error;
    fn from_str(s: &str) -> ::anyhow::Result<Self, Self::Err> {
        let plaintext: snarkvm_backend::prelude::Plaintext<N> = s.parse()?;
        plaintext.try_into()
    }
}
