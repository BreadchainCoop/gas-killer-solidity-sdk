// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import "@eigenlayer-middleware/BLSSignatureChecker.sol";
import {
    IBLSSignatureChecker, IBLSSignatureCheckerTypes
} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {ISlashingRegistryCoordinator} from "@eigenlayer-middleware/interfaces/ISlashingRegistryCoordinator.sol";
import {BN254} from "@eigenlayer-middleware/libraries/BN254.sol";
import "./StateTracker.sol";

/**
 * @title GasKillerSDK
 * @notice Base SDK for implementing Gas Killer functionality in contracts
 * @dev Inherit from this contract to add Gas Killer capabilities to your contract
 */
abstract contract GasKillerSDK is StateTracker {
    // The BLS signature checker contract
    BLSSignatureChecker public immutable blsSignatureChecker;
    // The address of the BLS signature checker contract
    address public constant BLS_SIG_CHECKER = address(0xB6861c61782aec28a14cF68cECf216Ad7f5F4e2D);

    // Namespace for the contract
    bytes public namespace;

    // The AVS service manager address
    address public avsAddress;

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public QUORUM_THRESHOLD = 66; // 66% threshold for quorum verification
    uint32 public BLOCK_STALE_MEASURE = 300;

    // Custom errors
    error InvalidTransitionIndex();
    error InvalidSignature();
    error InvalidStorageUpdates();
    error InvalidOperation();
    error InsufficientQuorumThreshold();
    error StaleBlockNumber();
    error FutureBlockNumber();
    error OnlyOwner();

    // Owner address for access control
    address public owner;

    constructor(address _avsAddress) {
        blsSignatureChecker = BLSSignatureChecker(BLS_SIG_CHECKER);
        avsAddress = _avsAddress;
        namespace = abi.encodePacked(avsAddress, "gaskiller");
        owner = msg.sender;
    }

    /**
     * @notice Modifier to restrict function access to the contract owner
     */
    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    /**
     * @notice Sets the quorum threshold percentage
     * @param newThreshold The new threshold value (0-100)
     */
    function setQuorumThreshold(uint8 newThreshold) external onlyOwner {
        require(newThreshold > 0 && newThreshold <= 100, "Invalid threshold value");
        QUORUM_THRESHOLD = newThreshold;
    }

    /**
     * @notice Sets the block stale measure
     * @param newBlockStaleMeasure The new block stale measure value
     */
    function setBlockStaleMeasure(uint32 newBlockStaleMeasure) external onlyOwner {
        require(newBlockStaleMeasure > 0, "Invalid block stale measure");
        BLOCK_STALE_MEASURE = newBlockStaleMeasure;
    }

    /**
     * @notice Function to verify if a signature is valid and contains correct storage updates
     * @param msgHash The hash of the message to verify
     * @param quorumNumbers The quorum numbers to check signatures for
     * @param referenceBlockNumber The block number to use as reference for operator set
     * @param storageUpdates The storage updates to verify
     * @param transitionIndex The transition index
     * @param targetAddr The target contract address
     * @param targetFunction The target function selector
     * @param nonSignerStakesAndSignature The non-signer stakes and signature data computed off-chain
     */
    function verifyAndUpdate(
        bytes32 msgHash,
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        bytes calldata storageUpdates,
        uint256 transitionIndex,
        address targetAddr,
        bytes4 targetFunction,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external trackState {
        // Check block number validity
        require(referenceBlockNumber < block.number, FutureBlockNumber());
        require((referenceBlockNumber + BLOCK_STALE_MEASURE) >= uint32(block.number), StaleBlockNumber());

        // Verify transition index and message hash
        require(transitionIndex + 1 == stateTransitionCount(), InvalidTransitionIndex());
        bytes32 expectedHash = sha256(abi.encode(transitionIndex, targetAddr, targetFunction, storageUpdates));
        require(expectedHash == msgHash, InvalidSignature());

        // Verify the signatures using checkSignatures
        (IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals, bytes32 signatoryRecordHash) =
        blsSignatureChecker.checkSignatures(msgHash, quorumNumbers, referenceBlockNumber, nonSignerStakesAndSignature);

        // Check that signatories own at least 66% of each quorum
        for (uint256 i = 0; i < quorumNumbers.length; i++) {
            require(
                stakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR
                    >= stakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD,
                InsufficientQuorumThreshold()
            );
        }

        // Apply the state changes
        _stateChangeHandler(storageUpdates);
    }

    /**
     * @notice Function to apply storage updates
     * @param storageUpdates The storage updates to apply
     */
    function _stateChangeHandler(bytes calldata storageUpdates) internal {
        //TODO: Implement state change handler
    }

    function decodeStorageUpdates(bytes calldata storageUpdates) internal returns (bytes memory) {
        //TODO: Implement storage updates decoding
    }
}
