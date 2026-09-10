// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.27;

import {
    IBLSSignatureChecker,
    IBLSSignatureCheckerTypes
} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IGasKillerSDK} from "../interface/IGasKillerSDK.sol";
import {ISchnorrGasKillerSDK} from "../schnorr/interface/ISchnorrGasKillerSDK.sol";
import {ISchnorrGasKillerSDKBatch, SchnorrTaskSubmission} from "../schnorr/interface/ISchnorrGasKillerSDKBatch.sol";
import {ISchnorrStakeRegistry} from "../schnorr/interface/ISchnorrStakeRegistry.sol";
import {StateTracker} from "../StateTracker.sol";
import {TransitionGuard} from "../TransitionGuard.sol";
import {StateChangeHandlerLib, StateUpdateType} from "../StateChangeHandlerLib.sol";

/// @title DualSchemeGasKillerSDK
/// @notice Transitional SDK base carrying both verification schemes: the BLS
///         `verifyAndUpdate` of `GasKillerSDK` and the aggregate-Schnorr
///         `verifyAndUpdate`/`verifyAndUpdateBatch` of `SchnorrGasKillerSDK`. Both
///         entrypoints are always live and both scheme interface IDs are always reported,
///         so one target settles against a BLS fleet and a Schnorr fleet alike.
///
/// @dev Migration usage:
///
///      - Inherit this in place of `GasKillerSDK` or `SchnorrGasKillerSDK`, and set both
///        verifiers in the constructor: `_setBlsSignatureChecker` and
///        `_setSchnorrRegistry`, alongside `_setAvsAddress`. That is the whole
///        integration: there is no mode to select and no transaction to send at cutover.
///      - Leaving a verifier unset makes that scheme's entrypoint unusable, so set both
///        even though only one fleet settles at a time.
///      - Move to `SchnorrGasKillerSDK` once the cutover has settled. `src/migration/` and
///        `test/migration/` are scheduled for removal at that point.
///
///      The task digest, the `StateTracker` transition counter, the `TransitionGuard`
///      latch, `StateChangeHandlerLib` application and each path's validation are identical
///      to the scheme-specific bases, so the off-chain signing path is unaffected. The two
///      schemes share the one transition counter and therefore settle into a single
///      sequence, in any order.
///
///      Both paths being live means either operator set's quorum can settle against the
///      target, so its trust assumption is the union of the two for as long as it inherits
///      this. That is the point during a migration window in which one party operates both
///      sets, and is the reason not to inherit this outside one.
abstract contract DualSchemeGasKillerSDK is
    StateTracker,
    TransitionGuard,
    ERC165,
    IGasKillerSDK,
    ISchnorrGasKillerSDK,
    ISchnorrGasKillerSDKBatch
{
    /// @custom:storage-location erc7201:gaskiller.DualSchemeGasKillerSDK.storage
    /// @dev Own namespace, distinct from the `GasKillerSDK` and `SchnorrGasKillerSDK` ones.
    ///      A contract inheriting this behind a proxy must set the AVS address, both
    ///      verifiers and the stale measure against this namespace.
    ///
    ///      Field order is load-bearing. `schnorrRegistry` and `blockStaleMeasure` fill one
    ///      slot exactly, which is the whole reason a settlement reads the config it needs
    ///      and no more: the Schnorr path touches that single slot, and the BLS path that
    ///      slot plus `blsSignatureChecker`. `avsAddress` is read by neither path, only by
    ///      its getter. Reordering these buys nothing and costs one path a cold `SLOAD` on
    ///      every settlement.
    struct DualSchemeSDKStorage {
        /// @notice The Schnorr stake registry verifying aggregate Schnorr quorums
        ISchnorrStakeRegistry schnorrRegistry;
        /// @notice Maximum number of blocks a reference block may lag behind the current block
        uint96 blockStaleMeasure;
        /// @notice The BLS signature checker contract used to verify aggregated BLS signatures
        IBLSSignatureChecker blsSignatureChecker;
        /// @notice The AVS service manager address
        address avsAddress;
    }

    // keccak256(abi.encode(uint256(keccak256("gaskiller.DualSchemeGasKillerSDK.storage")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant DUAL_SCHEME_SDK_STORAGE_LOCATION =
        0xa430b9d9078bbb41084913d0dada2f4e7e2e5b5ade5d562e9e118f0b5cb0ac00;

    /// @notice Denominator used when evaluating stake percentage thresholds (representing 100%)
    uint8 public constant THRESHOLD_DENOMINATOR = 100;

    /// @notice Minimum percentage of quorum stake that must have signed to approve a state
    ///         update (QUORUM_THRESHOLD/THRESHOLD_DENOMINATOR)
    uint8 public constant QUORUM_THRESHOLD = 66;

    /// @notice Default maximum age (in blocks) a reference block is considered valid when none is configured
    uint256 private constant DEFAULT_BLOCK_STALE_MEASURE = 300;

    /// @notice Thrown when the Schnorr stake registry rejects the aggregate quorum signature
    error InvalidQuorumSignature();

    /// @notice Thrown when `verifyAndUpdateBatch` is called with no submissions
    error EmptyBatch();

    /// @notice Thrown when a stale measure too large to store is configured
    error BlockStaleMeasureOverflow();

    // -------------------------------------------------------------------------
    // BLS settlement path
    // -------------------------------------------------------------------------

    /// @inheritdoc IGasKillerSDK
    function verifyAndUpdate(
        bytes32 msgHash,
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        bytes calldata storageUpdates,
        uint256 transitionIndex,
        bytes4 targetFunction,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external payable guardTransition trackState {
        require(referenceBlockNumber < block.number, FutureBlockNumber());
        require((uint256(referenceBlockNumber) + _getBlockStaleMeasure()) >= block.number, StaleBlockNumber());

        require(transitionIndex + 1 == stateTransitionCount(), InvalidTransitionIndex());
        bytes32 expectedHash = sha256(abi.encode(transitionIndex, address(this), targetFunction, storageUpdates));
        require(expectedHash == msgHash, InvalidSignature());

        IBLSSignatureChecker checker = _sto().blsSignatureChecker;
        (IBLSSignatureCheckerTypes.QuorumStakeTotals memory stakeTotals,) =
            checker.checkSignatures(msgHash, quorumNumbers, referenceBlockNumber, nonSignerStakesAndSignature);

        uint256 quorumCount = quorumNumbers.length;
        for (uint256 i = 0; i < quorumCount; ++i) {
            require(
                stakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR
                    >= stakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD,
                InsufficientQuorumThreshold()
            );
        }

        _stateChangeHandler(storageUpdates);
    }

    // -------------------------------------------------------------------------
    // Schnorr settlement path
    // -------------------------------------------------------------------------

    /// @inheritdoc ISchnorrGasKillerSDK
    function verifyAndUpdate(
        bytes32 msgHash,
        uint32 referenceBlockNumber,
        bytes calldata storageUpdates,
        uint256 transitionIndex,
        bytes4 targetFunction,
        uint256 s,
        address Raddr,
        address[] calldata nonSigners
    ) external payable guardTransition {
        _verifyAndUpdateOne(
            msgHash, referenceBlockNumber, storageUpdates, transitionIndex, targetFunction, s, Raddr, nonSigners
        );
    }

    /// @inheritdoc ISchnorrGasKillerSDKBatch
    /// @dev Batch semantics match `SchnorrGasKillerSDK.verifyAndUpdateBatch`.
    function verifyAndUpdateBatch(SchnorrTaskSubmission[] calldata submissions) external payable guardTransition {
        uint256 len = submissions.length;
        require(len != 0, EmptyBatch());
        for (uint256 i = 0; i < len; ++i) {
            SchnorrTaskSubmission calldata sub = submissions[i];
            // An already-settled index is skipped; a gap reverts inside _verifyAndUpdateOne.
            if (sub.transitionIndex + 1 <= stateTransitionCount()) continue;
            _verifyAndUpdateOne(
                sub.msgHash,
                sub.referenceBlockNumber,
                sub.storageUpdates,
                sub.transitionIndex,
                sub.targetFunction,
                sub.s,
                sub.Raddr,
                sub.nonSigners
            );
        }
    }

    /// @dev The single-transition Schnorr settlement path shared by both Schnorr entrypoints.
    function _verifyAndUpdateOne(
        bytes32 msgHash,
        uint32 referenceBlockNumber,
        bytes calldata storageUpdates,
        uint256 transitionIndex,
        bytes4 targetFunction,
        uint256 s,
        address Raddr,
        address[] calldata nonSigners
    ) private trackState {
        require(referenceBlockNumber < block.number, FutureBlockNumber());
        require((uint256(referenceBlockNumber) + _getBlockStaleMeasure()) >= block.number, StaleBlockNumber());

        require(transitionIndex + 1 == stateTransitionCount(), InvalidTransitionIndex());
        bytes32 expectedHash = sha256(abi.encode(transitionIndex, address(this), targetFunction, storageUpdates));
        require(expectedHash == msgHash, InvalidSignature());

        _verifyQuorum(msgHash, s, Raddr, nonSigners, referenceBlockNumber);

        _stateChangeHandler(storageUpdates);
    }

    /// @dev Verify the aggregate Schnorr quorum signature against the stake registry.
    function _verifyQuorum(
        bytes32 msgHash,
        uint256 s,
        address Raddr,
        address[] calldata nonSigners,
        uint32 referenceBlockNumber
    ) private view {
        bool ok = _sto().schnorrRegistry.isValidSignature(msgHash, s, Raddr, nonSigners, referenceBlockNumber);
        require(ok, InvalidQuorumSignature());
    }

    // -------------------------------------------------------------------------
    // Introspection and configuration
    // -------------------------------------------------------------------------

    /// @notice Query if a contract implements an interface
    /// @dev Reports `IGasKillerSDK`, `ISchnorrGasKillerSDK` and `ISchnorrGasKillerSDKBatch`.
    ///      A contract inheriting this alongside another ERC-165 module must override
    ///      `supportsInterface` and defer to `super` to report the union of both ID sets.
    /// @param interfaceId The interface identifier, as specified in ERC-165
    /// @return `true` if the contract implements `interfaceId` and `false` otherwise
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IGasKillerSDK).interfaceId || interfaceId == type(ISchnorrGasKillerSDK).interfaceId
            || interfaceId == type(ISchnorrGasKillerSDKBatch).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @inheritdoc TransitionGuard
    function inTransition() public view override(TransitionGuard, ISchnorrGasKillerSDKBatch) returns (bool locked) {
        return TransitionGuard.inTransition();
    }

    /// @notice Compute the expected message hash for a given transition, function, and storage updates
    /// @dev Identical to `GasKillerSDK.getMessageHash` and `SchnorrGasKillerSDK.getMessageHash`.
    /// @param transitionIndex The transition index
    /// @param targetFunction The target function selector
    /// @param storageUpdates The ABI-encoded storage updates
    /// @return The expected SHA-256 hash
    function getMessageHash(uint256 transitionIndex, bytes4 targetFunction, bytes calldata storageUpdates)
        external
        view
        returns (bytes32)
    {
        return sha256(abi.encode(transitionIndex, address(this), targetFunction, storageUpdates));
    }

    /// @notice Return the configured AVS service manager address
    /// @return The AVS address
    function avsAddress() external view returns (address) {
        return _sto().avsAddress;
    }

    /// @notice Return the configured BLS signature checker address
    /// @return The BLS signature checker address
    function blsSignatureChecker() external view returns (address) {
        return address(_sto().blsSignatureChecker);
    }

    /// @notice Return the configured Schnorr stake registry address
    /// @return The Schnorr stake registry address
    function schnorrRegistry() external view returns (address) {
        return address(_sto().schnorrRegistry);
    }

    /// @notice Return the namespace bytes derived from the AVS address
    /// @dev Computed on read as `abi.encodePacked(avsAddress, "gaskiller")`. Returns empty
    ///      bytes when the AVS address is unset.
    /// @return The namespace
    function namespace() external view returns (bytes memory) {
        address _avsAddress = _sto().avsAddress;
        if (_avsAddress == address(0)) {
            return "";
        }
        return abi.encodePacked(_avsAddress, "gaskiller");
    }

    /// @notice Return the configured block stale measure (or the default if unset)
    /// @return The block stale measure
    function blockStaleMeasure() external view returns (uint256) {
        return _getBlockStaleMeasure();
    }

    /// @notice Decode and execute ABI-encoded storage updates
    /// @param storageUpdates ABI-encoded `(StateUpdateType[], bytes[])` pair
    function _stateChangeHandler(bytes calldata storageUpdates) internal {
        (StateUpdateType[] memory types, bytes[] memory args) = abi.decode(storageUpdates, (StateUpdateType[], bytes[]));
        StateChangeHandlerLib._runStateUpdates(types, args);
    }

    /// @notice Set the AVS address
    /// @param _avsAddress The new AVS service manager address
    function _setAvsAddress(address _avsAddress) internal {
        _sto().avsAddress = _avsAddress;
    }

    /// @notice Set the BLS signature checker contract
    /// @param _blsSignatureChecker The new BLS signature checker address
    function _setBlsSignatureChecker(address _blsSignatureChecker) internal {
        _sto().blsSignatureChecker = IBLSSignatureChecker(_blsSignatureChecker);
    }

    /// @notice Set the Schnorr stake registry contract
    /// @param _registry The new Schnorr stake registry address
    function _setSchnorrRegistry(address _registry) internal {
        _sto().schnorrRegistry = ISchnorrStakeRegistry(_registry);
    }

    /// @notice Set the maximum number of blocks a reference block may lag behind the current block
    /// @param _blockStaleMeasure The new block stale measure value
    function _setBlockStaleMeasure(uint256 _blockStaleMeasure) internal {
        require(_blockStaleMeasure <= type(uint96).max, BlockStaleMeasureOverflow());
        _sto().blockStaleMeasure = uint96(_blockStaleMeasure);
    }

    /// @notice Return the block stale measure, falling back to the default when unset
    /// @return The effective block stale measure
    function _getBlockStaleMeasure() internal view returns (uint256) {
        uint256 value = _sto().blockStaleMeasure;
        return value == 0 ? DEFAULT_BLOCK_STALE_MEASURE : value;
    }

    /// @notice Load the ERC-7201 storage struct for DualSchemeGasKillerSDK
    /// @return $ The DualSchemeGasKillerSDK storage struct
    function _sto() private pure returns (DualSchemeSDKStorage storage $) {
        assembly {
            $.slot := DUAL_SCHEME_SDK_STORAGE_LOCATION
        }
    }
}
