// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {IERC165} from "forge-std/interfaces/IERC165.sol";
import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

/// @notice Represents an external storage slot access (address + slot)
struct ExternalStorageSlot {
    address contractAddress;
    bytes32 slot;
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
    error ExternalStorageSlotMismatch(address contractAddress, bytes32 slot);

    /**
     * @notice Function to verify if a signature is valid and contains correct storage updates
     * @param msgHash The hash of the message to verify
     * @param quorumNumbers The quorum numbers to check signatures for
     * @param referenceBlockNumber The block number to use as reference for operator set
     * @param storageUpdates The storage updates to verify
     * @param expectedExternalSlots Array of external storage slots that were read during execution (as proven in ZK proof)
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
        ExternalStorageSlot[] calldata expectedExternalSlots,
        uint256 transitionIndex,
        bytes32 anchorHash,
        address callerAddress,
        bytes calldata contractCalldata,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external;
}
