use ethers::prelude::abigen;

abigen!(
    IAxelarAmplifierGateway,
    "src/abi/$SOLIDITY_GATEWAY_VERSION/IAxelarAmplifierGateway.json"
);
abigen!(
    IBaseWeightedMultisig,
    "src/abi/$SOLIDITY_GATEWAY_VERSION/IBaseWeightedMultisig.json"
);
