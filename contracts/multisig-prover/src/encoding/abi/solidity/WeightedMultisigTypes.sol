// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @notice This struct represents the weighted signers payload
 * @param signers The list of signers
 * @param weights The list of weights
 * @param threshold The threshold for the signers
 */
struct WeightedSigner {
    address signer;
    uint128 weight;
}

/**
 * @notice This struct represents the weighted signers payload
 * @param signers The list of weighted signers
 * @param threshold The threshold for the weighted signers
 * @param nonce The nonce to distinguish different weighted signer sets
 */
struct WeightedSigners {
    WeightedSigner[] signers;
    uint128 threshold;
    bytes32 nonce;
}

/**
 * @notice This struct represents a proof for a message from the weighted signers
 * @param signers The weighted signers
 * @param signatures The list of signatures
 */
struct Proof {
    WeightedSigners signers;
    bytes[] signatures;
}
