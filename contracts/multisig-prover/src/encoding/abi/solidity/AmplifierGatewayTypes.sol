// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @notice This enum represents the different types of commands that can be processed by the Axelar Amplifier Gateway
 */
enum CommandType {
    ApproveMessages,
    RotateSigners
}

/**
 * @notice This struct represents a message that is to be processed by the Amplifier Gateway
 * @param sourceChain The chain from which the message originated
 * @param messageId The unique identifier for the message
 * @param sourceAddress The address from which the message originated
 * @param contractAddress The address of the contract that the message is intended for
 * @param payloadHash The hash of the payload that is to be processed
 */
struct Message {
    string sourceChain;
    string messageId;
    string sourceAddress;
    address contractAddress;
    bytes32 payloadHash;
}
