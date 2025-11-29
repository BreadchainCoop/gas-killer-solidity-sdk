// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {
    IBLSSignatureChecker,
    IBLSSignatureCheckerTypes
} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {IERC165} from "forge-std/interfaces/IERC165.sol";

import {IGasKillerSDK, ExternalCall} from "./interface/IGasKillerSDK.sol";
import {StateTracker} from "./StateTracker.sol";
import {StateChangeHandlerLib, StateUpdateType} from "./StateChangeHandlerLib.sol";

/**
 * @title GasKillerSDK
 * @notice Base SDK for implementing Gas Killer functionality in contracts
 * @dev Inherit from this contract to add Gas Killer capabilities to your contract
 *
 * ## Slashing Support
 *
 * The signed message format includes all values needed for slashing verification:
 * - transitionIndex: Sequential counter for replay protection
 * - address(this): Target contract being updated
 * - anchorHash: Block hash anchoring execution to specific Ethereum state
 * - callerAddress: The msg.sender for the original call
 * - contractCalldata: Full calldata (not just selector) for reproducibility
 * - storageUpdates: The claimed storage changes
 *
 * To slash malicious operators, a challenger can:
 * 1. Generate an SP1 proof of correct execution using the signed inputs
 * 2. Compare the proven storage updates with the signed storage updates
 * 3. If they differ, submit slashing proof to EigenLayer
 */
abstract contract GasKillerSDK is StateTracker, IGasKillerSDK {
    /// @custom:storage-location erc7201:gaskiller.GasKillerSDK.storage
    struct GasKillerSDKStorage {
        bytes namespace; // Namespace for the contract
        address avsAddress; // The AVS service manager address
        IBLSSignatureChecker blsSignatureChecker; // The BLS signature checker contract
    }

    // keccak256(abi.encode(uint256(keccak256("gaskiller.GasKillerSDK.storage")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant GAS_KILLER_SDK_STORAGE_LOCATION =
        0x321ebf629ed2e1e368f0890e8fdd95cf9a2ae5961b66a1805f0b2ec84e21d000;

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public constant QUORUM_THRESHOLD = 66; // 66% quorum threshold
    uint32 public constant BLOCK_STALE_MEASURE = 300;

    /**
     * @notice Function to verify if a signature is valid and contains correct storage updates
     * @dev The message hash must be computed as:
     *      sha256(abi.encode(transitionIndex, address(this), anchorHash, callerAddress, contractCalldata, storageUpdates, expectedExternalCalls))
     *      This format enables slashing by including all inputs needed to reproduce execution.
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
    ) external trackState {
        GasKillerSDKStorage storage $ = _getGasKillerSDKStorage();

        // Check block number validity
        require(referenceBlockNumber < block.number, FutureBlockNumber());
        require((referenceBlockNumber + BLOCK_STALE_MEASURE) >= uint32(block.number), StaleBlockNumber());

        // Verify transition index and message hash
        require(transitionIndex + 1 == stateTransitionCount(), InvalidTransitionIndex());

        // Compute expected hash with all slashing-required fields:
        // - transitionIndex: replay protection
        // - address(this): target contract
        // - anchorHash: block hash for state anchoring (enables slashing verification)
        // - callerAddress: msg.sender (affects execution via access control, balances)
        // - contractCalldata: full calldata with arguments (enables execution reproduction)
        // - storageUpdates: the claimed storage changes
        // - expectedExternalCalls: first-level external calls made during execution
        bytes32 expectedHash = sha256(abi.encode(
            transitionIndex,
            address(this),
            anchorHash,
            callerAddress,
            contractCalldata,
            storageUpdates,
            expectedExternalCalls
        ));
        require(expectedHash == msgHash, InvalidSignature());

        // Verify the signatures using checkSignatures
        (IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,) = $.blsSignatureChecker
            .checkSignatures(msgHash, quorumNumbers, referenceBlockNumber, nonSignerStakesAndSignature);

        // Check that signatories own at least 66% of each quorum
        for (uint256 i = 0; i < quorumNumbers.length; i++) {
            require(
                stakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR
                    >= stakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD,
                InsufficientQuorumThreshold()
            );
        }

        // Apply the state changes, verifying external call results match expected
        _stateChangeHandler(storageUpdates, expectedExternalCalls);
    }

    /**
     * @notice Query if a contract implements an interface
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return `true` if the contract implements `interfaceId` and `false` otherwise
     * @dev This implementation supports ERC165 and IGasKillerSDK interface detection
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IGasKillerSDK).interfaceId;
    }

    /**
     * @notice Function to get the expected hash for a given set of execution parameters
     * @dev This hash format enables slashing verification via SP1 proofs
     * @param transitionIndex The transition index
     * @param anchorHash The block hash anchoring the execution
     * @param callerAddress The caller address (msg.sender)
     * @param contractCalldata The full contract calldata
     * @param storageUpdates The storage updates
     * @param expectedExternalCalls The expected first-level external calls made during execution
     * @return bytes32 The expected message hash
     */
    function getMessageHash(
        uint256 transitionIndex,
        bytes32 anchorHash,
        address callerAddress,
        bytes calldata contractCalldata,
        bytes calldata storageUpdates,
        ExternalCall[] calldata expectedExternalCalls
    ) external view returns (bytes32) {
        return sha256(abi.encode(
            transitionIndex,
            address(this),
            anchorHash,
            callerAddress,
            contractCalldata,
            storageUpdates,
            expectedExternalCalls
        ));
    }

    /**
     * @notice Function to get the AVS address
     * @return address The AVS address
     */
    function avsAddress() external view returns (address) {
        return _getGasKillerSDKStorage().avsAddress;
    }

    /**
     * @notice Function to get the BLS signature checker address
     * @return address The BLS signature checker address
     */
    function blsSignatureChecker() external view returns (address) {
        return address(_getGasKillerSDKStorage().blsSignatureChecker);
    }

    /**
     * @notice Function to get the namespace
     * @return bytes The namespace
     */
    function namespace() external view returns (bytes memory) {
        return _getGasKillerSDKStorage().namespace;
    }

    /**
     * @notice Function to apply storage updates with external call verification
     * @param storageUpdates The storage updates to apply
     * @param expectedExternalCalls The expected first-level external calls made during execution
     */
    function _stateChangeHandler(bytes calldata storageUpdates, ExternalCall[] calldata expectedExternalCalls) internal {
        (StateUpdateType[] memory types, bytes[] memory args) = abi.decode(storageUpdates, (StateUpdateType[], bytes[]));
        StateChangeHandlerLib._runStateUpdates(types, args, expectedExternalCalls);
    }

    /**
     * @notice Internal function to set the AVS address
     * @dev Namespace is used to identify the contract in the AVS service manager
     * @param _avsAddress The new AVS address
     */
    function _setAvsAddress(address _avsAddress) internal {
        GasKillerSDKStorage storage $ = _getGasKillerSDKStorage();
        $.avsAddress = _avsAddress;
        $.namespace = abi.encodePacked($.avsAddress, "gaskiller");
    }

    /**
     * @notice Internal function to set the BLS signature checker address
     * @param _blsSignatureChecker The new BLS signature checker address
     */
    function _setBlsSignatureChecker(address _blsSignatureChecker) internal {
        GasKillerSDKStorage storage $ = _getGasKillerSDKStorage();
        $.blsSignatureChecker = IBLSSignatureChecker(_blsSignatureChecker);
    }

    /**
     * @notice Internal function to get the GasKillerSDK storage
     * @return $ The GasKillerSDK storage struct
     */
    function _getGasKillerSDKStorage() private pure returns (GasKillerSDKStorage storage $) {
        assembly {
            $.slot := GAS_KILLER_SDK_STORAGE_LOCATION
        }
    }
}
