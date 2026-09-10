// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IBLSSignatureCheckerTypes} from "@eigenlayer-middleware/interfaces/IBLSSignatureChecker.sol";

import {IGasKillerSDK} from "../../src/interface/IGasKillerSDK.sol";
import {ISchnorrGasKillerSDK} from "../../src/schnorr/interface/ISchnorrGasKillerSDK.sol";
import {
    ISchnorrGasKillerSDKBatch,
    SchnorrTaskSubmission
} from "../../src/schnorr/interface/ISchnorrGasKillerSDKBatch.sol";
import {ISchnorrStakeRegistry} from "../../src/schnorr/interface/ISchnorrStakeRegistry.sol";
import {DualSchemeGasKillerSDK} from "../../src/migration/DualSchemeGasKillerSDK.sol";
import {StateUpdateType} from "../../src/StateChangeHandlerLib.sol";

/// BLS checker stub that approves every submission at full stake. The dispatch control flow
/// under test is independent of real BLS verification.
contract MockBLSSignatureChecker {
    function checkSignatures(
        bytes32,
        bytes calldata quorumNumbers,
        uint32,
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature calldata
    ) external pure returns (IBLSSignatureCheckerTypes.QuorumStakeTotals memory totals, bytes32) {
        uint256 quorumCount = quorumNumbers.length;
        totals.signedStakeForQuorum = new uint96[](quorumCount);
        totals.totalStakeForQuorum = new uint96[](quorumCount);
        for (uint256 i = 0; i < quorumCount; ++i) {
            totals.signedStakeForQuorum[i] = 100;
            totals.totalStakeForQuorum[i] = 100;
        }
        return (totals, bytes32(0));
    }
}

/// Registry stub with a settable verdict, mirroring `SchnorrGasKillerSDK.t.sol`.
contract MockSchnorrRegistry is ISchnorrStakeRegistry {
    bool public verdict = true;

    function setVerdict(bool v) external {
        verdict = v;
    }

    function isValidSignature(bytes32, uint256, address, address[] calldata, uint256) external view returns (bool) {
        return verdict;
    }
}

/// Concrete migration target: stores a `value` at slot 0.
contract TestDualSchemeSDK is DualSchemeGasKillerSDK {
    uint256 public value; // slot 0

    constructor(address blsChecker, address schnorrRegistry_) {
        _setAvsAddress(address(0xA75));
        _setBlsSignatureChecker(blsChecker);
        _setSchnorrRegistry(schnorrRegistry_);
    }
}

contract DualSchemeGasKillerSDKTest is Test {
    MockBLSSignatureChecker internal blsChecker;
    MockSchnorrRegistry internal registry;
    TestDualSchemeSDK internal sdk;

    /// A single quorum, matching the mock checker's full-stake verdict.
    bytes internal constant QUORUMS = hex"00";

    function setUp() public {
        vm.roll(1000);
        blsChecker = new MockBLSSignatureChecker();
        registry = new MockSchnorrRegistry();
        sdk = new TestDualSchemeSDK(address(blsChecker), address(registry));
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    function _storeUpdate(bytes32 slot, bytes32 val) internal pure returns (bytes memory) {
        StateUpdateType[] memory types = new StateUpdateType[](1);
        types[0] = StateUpdateType.STORE;
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encode(slot, val);
        return abi.encode(types, args);
    }

    function _digest(uint256 transitionIndex, bytes4 targetFn, bytes memory updates) internal view returns (bytes32) {
        return sha256(abi.encode(transitionIndex, address(sdk), targetFn, updates));
    }

    /// Settles a transition on the BLS path at the next expected index.
    function _settleBls(bytes memory updates, bytes4 fn) internal {
        uint256 ti = sdk.stateTransitionCount();
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature memory nsss;
        sdk.verifyAndUpdate(_digest(ti, fn, updates), QUORUMS, uint32(block.number - 1), updates, ti, fn, nsss);
    }

    /// Settles a transition on the Schnorr path at the next expected index.
    function _settleSchnorr(bytes memory updates, bytes4 fn) internal {
        uint256 ti = sdk.stateTransitionCount();
        sdk.verifyAndUpdate(
            _digest(ti, fn, updates), uint32(block.number - 1), updates, ti, fn, 1, address(0x1), new address[](0)
        );
    }

    /// Builds one submission for `verifyAndUpdateBatch`.
    function _submission(uint256 transitionIndex, bytes4 fn, bytes memory updates)
        internal
        view
        returns (SchnorrTaskSubmission memory sub)
    {
        sub.msgHash = _digest(transitionIndex, fn, updates);
        sub.referenceBlockNumber = uint32(block.number - 1);
        sub.storageUpdates = updates;
        sub.transitionIndex = transitionIndex;
        sub.targetFunction = fn;
        sub.s = 1;
        sub.Raddr = address(0x1);
        sub.nonSigners = new address[](0);
    }

    // ---------------------------------------------------------------------
    // Routability: the whole point of the contract
    // ---------------------------------------------------------------------

    /// The router hard-codes these two IDs (`GAS_KILLER_INTERFACE_ID`,
    /// `SCHNORR_GAS_KILLER_INTERFACE_ID` in `gas_killer_common::bindings`) and refuses to
    /// settle against a target that does not report the one its own `SIGNATURE_SCHEME`
    /// selects. Pinning the literals here means a drift in either interface surfaces as a
    /// failing test rather than as a silently unroutable deployment.
    function test_reportsBothInterfaceIdsTheRouterProbes() public view {
        assertEq(type(IGasKillerSDK).interfaceId, bytes4(0x93de4531), "bls interface id drifted");
        assertEq(type(ISchnorrGasKillerSDK).interfaceId, bytes4(0x82b35a01), "schnorr interface id drifted");

        assertTrue(sdk.supportsInterface(bytes4(0x93de4531)), "routable by a bls fleet");
        assertTrue(sdk.supportsInterface(bytes4(0x82b35a01)), "routable by a schnorr fleet");
        assertTrue(sdk.supportsInterface(type(ISchnorrGasKillerSDKBatch).interfaceId), "batch id");
        assertTrue(sdk.supportsInterface(type(IERC165).interfaceId), "erc165 id");
        assertFalse(sdk.supportsInterface(0xffffffff), "invalid id");
    }

    // ---------------------------------------------------------------------
    // Both paths settle
    // ---------------------------------------------------------------------

    function test_settlesOnTheBlsPath() public {
        _settleBls(_storeUpdate(bytes32(0), bytes32(uint256(42))), bytes4(keccak256("set()")));

        assertEq(sdk.value(), 42, "bls STORE applied");
        assertEq(sdk.stateTransitionCount(), 1, "transition tracked");
    }

    function test_settlesOnTheSchnorrPath() public {
        _settleSchnorr(_storeUpdate(bytes32(0), bytes32(uint256(7))), bytes4(keccak256("set()")));

        assertEq(sdk.value(), 7, "schnorr STORE applied");
        assertEq(sdk.stateTransitionCount(), 1, "transition tracked");
    }

    function test_settlesABatchOnTheSchnorrPath() public {
        bytes4 fn = bytes4(keccak256("set()"));
        uint256 ti = sdk.stateTransitionCount();

        SchnorrTaskSubmission[] memory subs = new SchnorrTaskSubmission[](2);
        subs[0] = _submission(ti, fn, _storeUpdate(bytes32(0), bytes32(uint256(11))));
        subs[1] = _submission(ti + 1, fn, _storeUpdate(bytes32(0), bytes32(uint256(22))));

        sdk.verifyAndUpdateBatch(subs);

        assertEq(sdk.value(), 22, "last sub-transition wins");
        assertEq(sdk.stateTransitionCount(), ti + 2, "both transitions tracked");
    }

    /// The property the cutover actually rests on: the two schemes share one transition
    /// counter, so rounds from either fleet compose into one sequence in either order. A
    /// fleet restart mid-stream is therefore indistinguishable from two rounds of one
    /// scheme, and needs no transaction against the target.
    function test_bothSchemesSettleIntoOneSharedSequence() public {
        bytes4 fn = bytes4(keccak256("set()"));

        _settleBls(_storeUpdate(bytes32(0), bytes32(uint256(1))), fn);
        assertEq(sdk.stateTransitionCount(), 1, "bls settled index 0");

        _settleSchnorr(_storeUpdate(bytes32(0), bytes32(uint256(2))), fn);
        assertEq(sdk.stateTransitionCount(), 2, "schnorr settled index 1");
        assertEq(sdk.value(), 2, "schnorr state applied");

        // And back again. Neither path is one-way.
        _settleBls(_storeUpdate(bytes32(0), bytes32(uint256(3))), fn);
        assertEq(sdk.stateTransitionCount(), 3, "bls settled index 2");
        assertEq(sdk.value(), 3, "bls state applied");
    }

    // ---------------------------------------------------------------------
    // Drop-in equivalence with the two scheme-specific bases
    // ---------------------------------------------------------------------

    /// The quorum signs a digest computed off-chain; if this contract's digest differed from
    /// the base it replaces, every round would fail `InvalidSignature` at settlement.
    function test_digestIsTheSchemeAgnosticTaskHash() public view {
        bytes memory updates = _storeUpdate(bytes32(uint256(3)), bytes32(uint256(4)));
        bytes4 fn = bytes4(keccak256("set()"));

        assertEq(
            sdk.getMessageHash(9, fn, updates),
            sha256(abi.encode(uint256(9), address(sdk), fn, updates)),
            "digest is the scheme-agnostic task hash"
        );
    }

    function test_configGettersMirrorTheSchemeSpecificBases() public view {
        assertEq(sdk.avsAddress(), address(0xA75), "avs address");
        assertEq(sdk.blsSignatureChecker(), address(blsChecker), "bls checker");
        assertEq(sdk.schnorrRegistry(), address(registry), "schnorr registry");
        assertEq(sdk.blockStaleMeasure(), 300, "default stale measure");
        assertEq(sdk.namespace(), abi.encodePacked(address(0xA75), "gaskiller"), "namespace");
        assertEq(sdk.THRESHOLD_DENOMINATOR(), 100, "threshold denominator");
        assertEq(sdk.QUORUM_THRESHOLD(), 66, "quorum threshold");
    }

    // ---------------------------------------------------------------------
    // Shared validation still applies on both paths
    // ---------------------------------------------------------------------

    function test_blsPath_rejectsAFutureReferenceBlock() public {
        bytes4 fn = bytes4(keccak256("set()"));
        bytes memory updates = _storeUpdate(bytes32(0), bytes32(uint256(1)));
        uint256 ti = sdk.stateTransitionCount();
        bytes32 h = _digest(ti, fn, updates);
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature memory nsss;

        vm.expectRevert(IGasKillerSDK.FutureBlockNumber.selector);
        sdk.verifyAndUpdate(h, QUORUMS, uint32(block.number), updates, ti, fn, nsss);
    }

    function test_schnorrPath_rejectsAFutureReferenceBlock() public {
        bytes4 fn = bytes4(keccak256("set()"));
        bytes memory updates = _storeUpdate(bytes32(0), bytes32(uint256(1)));
        uint256 ti = sdk.stateTransitionCount();
        bytes32 h = _digest(ti, fn, updates);

        vm.expectRevert(IGasKillerSDK.FutureBlockNumber.selector);
        sdk.verifyAndUpdate(h, uint32(block.number), updates, ti, fn, 1, address(0x1), new address[](0));
    }

    function test_blsPath_rejectsAStaleReferenceBlock() public {
        bytes4 fn = bytes4(keccak256("set()"));
        bytes memory updates = _storeUpdate(bytes32(0), bytes32(uint256(1)));
        uint256 ti = sdk.stateTransitionCount();
        bytes32 h = _digest(ti, fn, updates);
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature memory nsss;

        vm.expectRevert(IGasKillerSDK.StaleBlockNumber.selector);
        sdk.verifyAndUpdate(h, QUORUMS, uint32(block.number - 301), updates, ti, fn, nsss);
    }

    function test_schnorrPath_rejectsAStaleReferenceBlock() public {
        bytes4 fn = bytes4(keccak256("set()"));
        bytes memory updates = _storeUpdate(bytes32(0), bytes32(uint256(1)));
        uint256 ti = sdk.stateTransitionCount();
        bytes32 h = _digest(ti, fn, updates);

        vm.expectRevert(IGasKillerSDK.StaleBlockNumber.selector);
        sdk.verifyAndUpdate(h, uint32(block.number - 301), updates, ti, fn, 1, address(0x1), new address[](0));
    }

    function test_blsPath_rejectsAMismatchedDigest() public {
        bytes4 fn = bytes4(keccak256("set()"));
        bytes memory updates = _storeUpdate(bytes32(0), bytes32(uint256(1)));
        uint256 ti = sdk.stateTransitionCount();
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature memory nsss;

        vm.expectRevert(IGasKillerSDK.InvalidSignature.selector);
        sdk.verifyAndUpdate(bytes32(uint256(1)), QUORUMS, uint32(block.number - 1), updates, ti, fn, nsss);
    }

    function test_schnorrPath_rejectsAMismatchedDigest() public {
        bytes4 fn = bytes4(keccak256("set()"));
        bytes memory updates = _storeUpdate(bytes32(0), bytes32(uint256(1)));
        uint256 ti = sdk.stateTransitionCount();

        vm.expectRevert(IGasKillerSDK.InvalidSignature.selector);
        sdk.verifyAndUpdate(
            bytes32(uint256(1)), uint32(block.number - 1), updates, ti, fn, 1, address(0x1), new address[](0)
        );
    }

    /// One counter means one index: a submission on either path must claim the next one, so
    /// the two fleets cannot replay or skip each other's transitions.
    function test_bothPaths_rejectAWrongTransitionIndex() public {
        bytes4 fn = bytes4(keccak256("set()"));
        bytes memory updates = _storeUpdate(bytes32(0), bytes32(uint256(1)));
        bytes32 h = _digest(5, fn, updates);
        IBLSSignatureCheckerTypes.NonSignerStakesAndSignature memory nsss;

        vm.expectRevert(IGasKillerSDK.InvalidTransitionIndex.selector);
        sdk.verifyAndUpdate(h, QUORUMS, uint32(block.number - 1), updates, 5, fn, nsss);

        vm.expectRevert(IGasKillerSDK.InvalidTransitionIndex.selector);
        sdk.verifyAndUpdate(h, uint32(block.number - 1), updates, 5, fn, 1, address(0x1), new address[](0));
    }

    function test_schnorrPath_rejectsARegistryVerdictOfFalse() public {
        registry.setVerdict(false);

        bytes4 fn = bytes4(keccak256("set()"));
        bytes memory updates = _storeUpdate(bytes32(0), bytes32(uint256(1)));
        uint256 ti = sdk.stateTransitionCount();
        bytes32 h = _digest(ti, fn, updates);

        vm.expectRevert(DualSchemeGasKillerSDK.InvalidQuorumSignature.selector);
        sdk.verifyAndUpdate(h, uint32(block.number - 1), updates, ti, fn, 1, address(0x1), new address[](0));
    }

    function test_batch_rejectsAnEmptySubmissionSet() public {
        vm.expectRevert(DualSchemeGasKillerSDK.EmptyBatch.selector);
        sdk.verifyAndUpdateBatch(new SchnorrTaskSubmission[](0));
    }
}
