// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {IERC165} from "forge-std/interfaces/IERC165.sol";
import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/// @notice Represents a first-level external call made during contract execution
/// @dev Captures the target, calldata, and expected result for verification at runtime
struct ExternalCall {
    address target;         // The contract being called
    bytes callData;         // The calldata sent to the target
    bytes expectedResult;   // The expected return data from the call
}

/**
 * @title IGasKillerSDK
 * @notice Interface for GasKillerSDK contracts
 * @dev This interface defines the core functionality that GasKillerSDK implementations must provide
 */
interface IGasKillerSDK is IERC165 {
    // Custom errors
    error InvalidTransitionIndex();
    error InvalidSignature();
    error InvalidStorageUpdates();
    error InvalidOperation();
    error InsufficientQuorumThreshold();
    error StaleBlockNumber();
    error FutureBlockNumber();
    error ExternalCallResultMismatch(address target, bytes callData, bytes expectedResult, bytes actualResult);

    /**
     * @notice Function to verify if a signature is valid and contains correct storage updates
     * @param msgHash The hash of the message to verify
     * @param quorumNumbers The quorum numbers to check signatures for
     * @param referenceBlockNumber The block number to use as reference for operator set
     * @param storageUpdates The storage updates to verify
     * @param expectedExternalCalls Array of first-level external calls made during execution (as proven in ZK proof)
     * @param transitionIndex The transition index
     * @param anchorHash The block hash anchoring the execution to a specific Ethereum state
     * @param callerAddress The address that initiated the original call (msg.sender)
     * @param contractCalldata The full calldata for the contract call (not just selector)
     * @param nonSignerStakesAndSignature The non-signer stakes and signature data computed off-chain
     */
    function verifyAndUpdate(
        bytes32 msgHash,
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        bytes calldata storageUpdates,
        ExternalCall[] calldata expectedExternalCalls,
        uint256 transitionIndex,
        bytes32 anchorHash,
        address callerAddress,
        bytes calldata contractCalldata,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external;
}
