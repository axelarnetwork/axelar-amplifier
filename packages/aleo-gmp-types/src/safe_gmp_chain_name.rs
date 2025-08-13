use std::str::FromStr;

use aleo_string_encoder::StringEncoder;
use error_stack::{ensure, Report};
use router_api::ChainNameRaw;

use super::GmpChainName;
use crate::error::Error;

/// A safe GMP chain name that can be used in communication between the Aleo network and Axelar
/// network.
/// Axelar defines chain names at `ChainNameRaw` type, and to be sure that the same rules applied
/// on Aleo as well we use this type to convert chain names between Aleo and Axelar networks.
pub struct SafeGmpChainName {
    chain_name: GmpChainName,
}

impl SafeGmpChainName {
    pub fn new(chain_name: GmpChainName) -> Result<Self, Report<Error>> {
        let encoded_chain_name = StringEncoder::from_slice(&chain_name)
            .decode()
            .map_err(Error::from)?;

        ensure!(
            ChainNameRaw::is_raw_chain_name(&encoded_chain_name),
            Error::InvalidChainName(encoded_chain_name.clone())
        );

        Ok(Self { chain_name })
    }

    pub fn chain_name(self) -> GmpChainName {
        self.chain_name
    }
}

impl FromStr for SafeGmpChainName {
    type Err = Error;

    fn from_str(chain_name: &str) -> Result<Self, Self::Err> {
        let chain_name_raw = ChainNameRaw::from_str(chain_name)?;
        Self::try_from(chain_name_raw)
    }
}

impl TryFrom<&ChainNameRaw> for SafeGmpChainName {
    type Error = Error;

    fn try_from(chain_name: &ChainNameRaw) -> Result<Self, Self::Error> {
        let encoded = StringEncoder::encode_string(chain_name.as_ref())?.to_array()?;
        Ok(Self {
            chain_name: encoded,
        })
    }
}

impl TryFrom<ChainNameRaw> for SafeGmpChainName {
    type Error = Error;

    fn try_from(chain_name: ChainNameRaw) -> Result<Self, Self::Error> {
        Self::try_from(&chain_name)
    }
}

impl TryFrom<SafeGmpChainName> for ChainNameRaw {
    type Error = Error;

    fn try_from(aleo_gmp_chain_name: SafeGmpChainName) -> Result<Self, Self::Error> {
        let decoded_chain_name =
            StringEncoder::from_slice(&aleo_gmp_chain_name.chain_name).decode()?;
        Ok(Self::try_from(decoded_chain_name)?)
    }
}
