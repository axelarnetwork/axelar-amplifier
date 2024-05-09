// Source: contracts/interfaces/IAxelarAmplifierGateway.sol

pragma solidity ^0.8.0;

// SPDX-License-Identifier: MIT

// File contracts/interfaces/IAxelarGMPGateway.sol

/**
 * @title IAxelarGMPGateway
 * @dev Interface for the Axelar Gateway that supports general message passing and contract call execution.
 */
interface IAxelarGMPGateway {
    /**
     * @notice Emitted when a contract call is made through the gateway.
     * @dev Logs the attempt to call a contract on another chain.
     * @param sender The address of the sender who initiated the contract call.
     * @param destinationChain The name of the destination chain.
     * @param destinationContractAddress The address of the contract on the destination chain.
     * @param payloadHash The keccak256 hash of the sent payload data.
     * @param payload The payload data used for the contract call.
     */
    event ContractCall(
        address indexed sender,
        string destinationChain,
        string destinationContractAddress,
        bytes32 indexed payloadHash,
        bytes payload
    );

    /**
     * @notice Sends a contract call to another chain.
     * @dev Initiates a cross-chain contract call through the gateway to the specified destination chain and contract.
     * @param destinationChain The name of the destination chain.
     * @param contractAddress The address of the contract on the destination chain.
     * @param payload The payload data to be used in the contract call.
     */
    function callContract(
        string calldata destinationChain,
        string calldata contractAddress,
        bytes calldata payload
    ) external;

    /**
     * @notice Checks if a contract call is approved.
     * @dev Determines whether a given contract call, identified by the commandId and payloadHash, is approved.
     * @param commandId The identifier of the command to check.
     * @param sourceChain The name of the source chain.
     * @param sourceAddress The address of the sender on the source chain.
     * @param contractAddress The address of the contract where the call will be executed.
     * @param payloadHash The keccak256 hash of the payload data.
     * @return True if the contract call is approved, false otherwise.
     */
    function isContractCallApproved(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        address contractAddress,
        bytes32 payloadHash
    ) external view returns (bool);

    /**
     * @notice Validates and approves a contract call.
     * @dev Validates the given contract call information and marks it as approved if valid.
     * @param commandId The identifier of the command to validate.
     * @param sourceChain The name of the source chain.
     * @param sourceAddress The address of the sender on the source chain.
     * @param payloadHash The keccak256 hash of the payload data.
     * @return True if the contract call is validated and approved, false otherwise.
     */
    function validateContractCall(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external returns (bool);

    /**
     * @notice Checks if a command has been executed.
     * @dev Determines whether a command, identified by the commandId, has been executed.
     * @param commandId The identifier of the command to check.
     * @return True if the command has been executed, false otherwise.
     */
    function isCommandExecuted(bytes32 commandId) external view returns (bool);
}

// File contracts/interfaces/IBaseAmplifierGateway.sol

/**
 * @title IBaseAmplifierGateway
 * @dev Interface for the Base Axelar Amplifier Gateway that supports cross-chain messaging.
 */
interface IBaseAmplifierGateway is IAxelarGMPGateway {
    /**********\
    |* Errors *|
    \**********/

    error InvalidMessages();

    /**
     * @notice Emitted when a contract call has been executed.
     * @dev Logs the execution of an approved contract call.
     * @param commandId The identifier of the command that was executed.
     */
    event ContractCallExecuted(bytes32 indexed commandId);

    /**
     * @notice Emitted when a cross-chain contract call is approved.
     * @param commandId The identifier of the command to execute.
     * @param messageId The message id for the message.
     * @param sourceChain The name of the source chain from whence the command came.
     * @param sourceAddress The address of the sender on the source chain.
     * @param contractAddress The address of the contract where the call will be executed.
     * @param payloadHash The keccak256 hash of the approved payload data.
     */
    event ContractCallApproved(
        bytes32 indexed commandId,
        string messageId,
        string sourceChain,
        string sourceAddress,
        address indexed contractAddress,
        bytes32 indexed payloadHash
    );

    /**
     * @notice Checks if a contract call is approved.
     * @dev Determines whether a given contract call, identified by the commandId and payloadHash, is approved.
     * @param messageId The unique identifier of the message.
     * @param sourceChain The name of the source chain.
     * @param sourceAddress The address of the sender on the source chain.
     * @param contractAddress The address of the contract where the call will be executed.
     * @param payloadHash The keccak256 hash of the payload data.
     * @return True if the contract call is approved, false otherwise.
     */
    function isMessageApproved(
        string calldata messageId,
        string calldata sourceChain,
        string calldata sourceAddress,
        address contractAddress,
        bytes32 payloadHash
    ) external view returns (bool);

    /**
     * @notice Checks if a message is executed.
     * @dev Determines whether a given message, identified by the sourceChain and messageId is executed.
     * @param sourceChain The name of the source chain.
     * @param messageId The unique identifier of the message.
     * @return True if the message is executed, false otherwise.
     */
    function isMessageExecuted(string calldata sourceChain, string calldata messageId) external view returns (bool);

    /**
     * @notice Validates and approves a contract call using messageId.
     * @dev Validates the given contract call information and marks it as approved if valid.
     * @param messageId The unique identifier of the message.
     * @param sourceChain The name of the source chain.
     * @param sourceAddress The address of the sender on the source chain.
     * @param payloadHash The keccak256 hash of the payload data.
     * @return True if the contract call is validated and approved, false otherwise.
     */
    function validateMessage(
        string calldata messageId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external returns (bool);

    /**
     * @notice Compute the commandId for a `Message`.
     * @param sourceChain The name of the source chain as registered on Axelar.
     * @param messageId The unique message id for the message.
     * @return The commandId for the message.
     */
    function messageToCommandId(string calldata sourceChain, string calldata messageId) external pure returns (bytes32);
}

// File contracts/interfaces/IContractIdentifier.sol

// General interface for upgradable contracts
interface IContractIdentifier {
    /**
     * @notice Returns the contract ID. It can be used as a check during upgrades.
     * @dev Meant to be overridden in derived contracts.
     * @return bytes32 The contract ID
     */
    function contractId() external pure returns (bytes32);
}

// File contracts/interfaces/IImplementation.sol

interface IImplementation is IContractIdentifier {
    error NotProxy();

    function setup(bytes calldata data) external;
}

// File contracts/interfaces/IOwnable.sol

/**
 * @title IOwnable Interface
 * @notice IOwnable is an interface that abstracts the implementation of a
 * contract with ownership control features. It's commonly used in upgradable
 * contracts and includes the functionality to get current owner, transfer
 * ownership, and propose and accept ownership.
 */
interface IOwnable {
    error NotOwner();
    error InvalidOwner();
    error InvalidOwnerAddress();

    event OwnershipTransferStarted(address indexed newOwner);
    event OwnershipTransferred(address indexed newOwner);

    /**
     * @notice Returns the current owner of the contract.
     * @return address The address of the current owner
     */
    function owner() external view returns (address);

    /**
     * @notice Returns the address of the pending owner of the contract.
     * @return address The address of the pending owner
     */
    function pendingOwner() external view returns (address);

    /**
     * @notice Transfers ownership of the contract to a new address
     * @param newOwner The address to transfer ownership to
     */
    function transferOwnership(address newOwner) external;

    /**
     * @notice Proposes to transfer the contract's ownership to a new address.
     * The new owner needs to accept the ownership explicitly.
     * @param newOwner The address to transfer ownership to
     */
    function proposeOwnership(address newOwner) external;

    /**
     * @notice Transfers ownership to the pending owner.
     * @dev Can only be called by the pending owner
     */
    function acceptOwnership() external;
}

// File contracts/interfaces/IUpgradable.sol

// General interface for upgradable contracts
interface IUpgradable is IOwnable, IImplementation {
    error InvalidCodeHash();
    error InvalidImplementation();
    error SetupFailed();

    event Upgraded(address indexed newImplementation);

    function implementation() external view returns (address);

    function upgrade(
        address newImplementation,
        bytes32 newImplementationCodeHash,
        bytes calldata params
    ) external;
}

// File contracts/types/AmplifierGatewayTypes.sol

/**
 * @notice This enum represents the different types of commands that can be processed by the Axelar Amplifier Gateway
 */
enum CommandType {
    ApproveMessages,
    RotateSigners
}

/**
 * @notice This struct represents a message that is to be processed by the Amplifier Gateway
 * @param messageId The unique identifier for the message
 * @param sourceChain The chain from which the message originated
 * @param sourceAddress The address from which the message originated
 * @param contractAddress The address of the contract that the message is intended for
 * @param payloadHash The hash of the payload that is to be processed
 */
struct Message {
    string messageId;
    string sourceChain;
    string sourceAddress;
    address contractAddress;
    bytes32 payloadHash;
}

// File contracts/types/WeightedMultisigTypes.sol

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

// File contracts/interfaces/IAxelarAmplifierGateway.sol

/**
 * @title IAxelarAmplifierGateway
 * @dev Interface for the Axelar Gateway that supports general message passing and contract call execution.
 */
interface IAxelarAmplifierGateway is IBaseAmplifierGateway, IUpgradable {
    error NotLatestSigners();
    error AlreadyRotated();

    /**
     * @notice Approves an array of messages, signed by the Axelar signers.
     * @param  messages The array of messages to verify.
     * @param  proof The proof signed by the Axelar signers for this command.
     */
    function approveMessages(Message[] calldata messages, Proof calldata proof) external;

    /**
     * @notice Update the signer data for the auth module, signed by the Axelar signers.
     * @param  newSigners The data for the new signers.
     * @param  proof The proof signed by the Axelar signers for this command.
     */
    function rotateSigners(WeightedSigners memory newSigners, Proof calldata proof) external;

    /**
     * @notice This function takes dataHash and proof and reverts if proof is invalid
     * @param dataHash The hash of the data being signed
     * @param proof The proof from Axelar signers
     * @return isLatestSigners True if provided signers are the current ones
     */
    function validateProof(bytes32 dataHash, Proof calldata proof) external view returns (bool isLatestSigners);
}
