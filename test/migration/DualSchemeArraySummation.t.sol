// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {DualSchemeArraySummation} from "../../src/migration/examples/DualSchemeArraySummation.sol";
import {IGasKillerSDK} from "../../src/interface/IGasKillerSDK.sol";
import {ISchnorrGasKillerSDK} from "../../src/schnorr/interface/ISchnorrGasKillerSDK.sol";

/// Minimal stand-in: this suite covers the example's own wiring, meaning constructor
/// validation and routability. Signature verification is covered against the base in
/// `DualSchemeGasKillerSDK.t.sol`.
contract StubVerifier {
    uint256 public anything;
}

contract DualSchemeArraySummationTest is Test {
    address internal avs = makeAddr("AVS");

    StubVerifier internal blsChecker;
    StubVerifier internal registry;

    function setUp() public {
        blsChecker = new StubVerifier();
        registry = new StubVerifier();
    }

    function _deploy() internal returns (DualSchemeArraySummation) {
        return new DualSchemeArraySummation(avs, address(blsChecker), address(registry), 8, 100, 1);
    }

    function test_deploysWithBothVerifiersWired() public {
        DualSchemeArraySummation target = _deploy();

        assertEq(target.avsAddress(), avs, "avs address");
        assertEq(target.blsSignatureChecker(), address(blsChecker), "bls checker");
        assertEq(target.schnorrRegistry(), address(registry), "schnorr registry");
        assertEq(target.getArrayLength(), 8, "array initialised");
    }

    /// Both verifiers are mandatory: a target missing one is one that a fleet running that
    /// scheme will route to and then fail to settle against.
    function test_rejectsAMissingVerifier() public {
        vm.expectRevert(DualSchemeArraySummation.InvalidConfiguration.selector);
        new DualSchemeArraySummation(avs, address(0), address(registry), 8, 100, 1);

        vm.expectRevert(DualSchemeArraySummation.InvalidConfiguration.selector);
        new DualSchemeArraySummation(avs, address(blsChecker), address(0), 8, 100, 1);

        vm.expectRevert(DualSchemeArraySummation.InvalidConfiguration.selector);
        new DualSchemeArraySummation(address(0), address(blsChecker), address(registry), 8, 100, 1);
    }

    function test_rejectsAnUnusableArrayConfiguration() public {
        vm.expectRevert(DualSchemeArraySummation.InvalidConfiguration.selector);
        new DualSchemeArraySummation(avs, address(blsChecker), address(registry), 0, 100, 1);

        vm.expectRevert(DualSchemeArraySummation.InvalidConfiguration.selector);
        new DualSchemeArraySummation(avs, address(blsChecker), address(registry), 8, 0, 1);
    }

    /// The example must be routable by a fleet of either scheme, which is what makes the
    /// cutover a no-op for its operators.
    function test_isRoutableByEitherFleet() public {
        DualSchemeArraySummation target = _deploy();

        assertTrue(target.supportsInterface(type(IGasKillerSDK).interfaceId), "bls id");
        assertTrue(target.supportsInterface(type(ISchnorrGasKillerSDK).interfaceId), "schnorr id");
    }

    /// `sum` is `trackState`, so calling it advances the counter the settlement path checks
    /// against, unchanged from the two scheme-specific examples.
    function test_trackedFunctionsAdvanceTheTransitionCounter() public {
        DualSchemeArraySummation target = _deploy();
        uint256 before = target.stateTransitionCount();

        target.sum(new uint256[](0));

        assertEq(target.stateTransitionCount(), before + 1, "sum tracked");
        assertGt(target.currentSum(), 0, "sum computed");
    }
}
