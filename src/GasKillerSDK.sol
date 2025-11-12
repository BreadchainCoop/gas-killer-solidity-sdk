// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {
    IBLSSignatureChecker,
    IBLSSignatureCheckerTypes
} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {IERC165} from "forge-std/interfaces/IERC165.sol";

import {IGasKillerSDK} from "./interface/IGasKillerSDK.sol";
import {StateTracker} from "./StateTracker.sol";
import {StateChangeHandlerLib, StateUpdateType} from "./StateChangeHandlerLib.sol";

/**
 * @title GasKillerSDK
 * @notice Base SDK for implementing Gas Killer functionality in contracts
 * @dev Inherit from this contract to add Gas Killer capabilities to your contract
 */
abstract contract GasKillerSDK is StateTracker, IGasKillerSDK {
    bytes public namespace;
    address public avsAddress;

    // The BLS signature checker contract
    IBLSSignatureChecker public immutable BLS_SIGNATURE_CHECKER;

    // Constants for stake threshold checking
    uint8 public constant THRESHOLD_DENOMINATOR = 100;
    uint8 public constant QUORUM_THRESHOLD = 66; // 66% quorum threshold
    uint32 public constant BLOCK_STALE_MEASURE = 300;

    /**
     * @notice Constructor
     * @param _avsAddress The address of the AVS service manager
     * @param _blsSignatureChecker The address of the BLS signature checker
     */
    constructor(address _avsAddress, address _blsSignatureChecker) {
        _setAvsAddress(_avsAddress);
        BLS_SIGNATURE_CHECKER = IBLSSignatureChecker(_blsSignatureChecker);
    }

    /**
     * @notice Function to verify if a signature is valid and contains correct storage updates
     * @param msgHash The hash of the message to verify
     * @param quorumNumbers The quorum numbers to check signatures for
     * @param referenceBlockNumber The block number to use as reference for operator set
     * @param storageUpdates The storage updates to verify
     * @param transitionIndex The transition index
     * @param targetFunction The target function selector
     * @param nonSignerStakesAndSignature The non-signer stakes and signature data computed off-chain
     */
    function verifyAndUpdate(
        bytes32 msgHash,
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        bytes calldata storageUpdates,
        uint256 transitionIndex,
        bytes4 targetFunction,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external trackState {
        // Check block number validity
        require(referenceBlockNumber < block.number, FutureBlockNumber());
        require((referenceBlockNumber + BLOCK_STALE_MEASURE) >= uint32(block.number), StaleBlockNumber());

        // Verify transition index and message hash
        require(transitionIndex + 1 == stateTransitionCount(), InvalidTransitionIndex());
        bytes32 expectedHash = sha256(abi.encode(transitionIndex, address(this), targetFunction, storageUpdates));
        require(expectedHash == msgHash, InvalidSignature());

        // Verify the signatures using checkSignatures
        (IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,) = BLS_SIGNATURE_CHECKER.checkSignatures(
            msgHash, quorumNumbers, referenceBlockNumber, nonSignerStakesAndSignature
        );

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
     * @notice Query if a contract implements an interface
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return `true` if the contract implements `interfaceId` and `false` otherwise
     * @dev This implementation supports ERC165 and IGasKillerSDK interface detection
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IGasKillerSDK).interfaceId;
    }

    /**
     * @notice Function to get the expected hash for a given transition index, target function, and storage updates
     * @param transitionIndex The transition index
     * @param targetFunction The target function selector
     * @param storageUpdates The storage updates
     * @return bytes32 The expected hash
     */
    function getMessageHash(uint256 transitionIndex, bytes4 targetFunction, bytes calldata storageUpdates)
        external
        view
        returns (bytes32)
    {
        return sha256(abi.encode(transitionIndex, address(this), targetFunction, storageUpdates));
    }

    /**
     * @notice Function to apply storage updates
     * @param storageUpdates The storage updates to apply
     */
    function _stateChangeHandler(bytes calldata storageUpdates) internal {
        (StateUpdateType[] memory types, bytes[] memory args) = abi.decode(storageUpdates, (StateUpdateType[], bytes[]));
        StateChangeHandlerLib._runStateUpdates(types, args);
    }

    /**
     * @notice Internal function to set the AVS address
     * @dev Namespace is used to identify the contract in the AVS service manager
     * @param _avsAddress The new AVS address
     */
    function _setAvsAddress(address _avsAddress) internal {
        avsAddress = _avsAddress;
        namespace = abi.encodePacked(avsAddress, "gaskiller");
    }
}
