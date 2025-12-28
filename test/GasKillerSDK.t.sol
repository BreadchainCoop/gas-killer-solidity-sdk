// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {IERC165} from "forge-std/interfaces/IERC165.sol";

import "../src/GasKillerSDK.sol";
import "./exposed/GasKillerSDKExposed.sol";
import {StateUpdateType} from "../src/StateChangeHandlerLib.sol";
import {StateChangeHandlerLib} from "../src/StateChangeHandlerLib.sol";
import {ExternalCall} from "../src/interface/IGasKillerSDK.sol";

contract GasKillerSDKTest is Test {
    GasKillerSDKExposed public sdk;

    function setUp() public {
        sdk = new GasKillerSDKExposed(makeAddr("AVS"), makeAddr("BLS_SIG_CHECKER"));
    }

    function test_stateChangeHandlerExternal_Store() public {
        StateUpdateType[] memory types = new StateUpdateType[](1);
        types[0] = StateUpdateType.STORE;

        bytes[] memory args = new bytes[](1);
        bytes32 slot = bytes32(uint256(1));
        bytes32 value = bytes32(uint256(100));
        args[0] = abi.encode(slot, value);

        ExternalCall[] memory expectedExternalCalls = new ExternalCall[](0);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalCalls);

        assertEq(vm.load(address(sdk), slot), value);
    }

    function test_stateChangeHandlerExternal_Call() public {
        // Deploy a simple target contract
        SimpleTarget target = new SimpleTarget();

        StateUpdateType[] memory types = new StateUpdateType[](1);
        types[0] = StateUpdateType.CALL;

        // CALL args: (address target, uint256 value, bytes calldata)
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encode(address(target), uint256(0), abi.encodeWithSignature("setValue(uint256)", 42));

        ExternalCall[] memory expectedExternalCalls = new ExternalCall[](0);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalCalls);

        assertEq(target.value(), 42);
    }

    function test_stateChangeHandlerExternal_Call_RevertingContext() public {
        SimpleTarget target = new SimpleTarget();

        StateUpdateType[] memory types = new StateUpdateType[](1);
        types[0] = StateUpdateType.CALL;

        // CALL args: (address target, uint256 value, bytes calldata)
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encode(address(target), uint256(0), abi.encodeWithSignature("revertCall()"));

        vm.expectRevert(
            abi.encodeWithSelector(
                StateChangeHandlerLib.RevertingContext.selector,
                0,
                address(target),
                bytes("reverted"),
                abi.encodeWithSignature("revertCall()")
            )
        );
        ExternalCall[] memory expectedExternalCalls = new ExternalCall[](0);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalCalls);
    }

    function test_stateChangeHandlerExternal_Log1() public {
        StateUpdateType[] memory types = new StateUpdateType[](1);
        types[0] = StateUpdateType.LOG1;

        bytes[] memory args = new bytes[](1);
        args[0] = abi.encode(bytes("log data"), keccak256("Log1(bytes)"));
        console.logBytes(args[0]);

        vm.recordLogs();

        ExternalCall[] memory expectedExternalCalls = new ExternalCall[](0);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalCalls);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics.length, 1);
        assertEq(logs[0].topics[0], keccak256("Log1(bytes)"));
        assertEq(logs[0].data, "log data");
    }

    function test_stateChangeHandlerExternal_InvalidArguments() public {
        StateUpdateType[] memory types = new StateUpdateType[](2);
        bytes[] memory args = new bytes[](1);

        ExternalCall[] memory expectedExternalCalls = new ExternalCall[](0);
        vm.expectRevert(StateChangeHandlerLib.InvalidArguments.selector);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalCalls);
    }

    function test_ERC165_supportsInterface() public {
        // Test that the contract supports IERC165
        assertTrue(sdk.supportsInterface(type(IERC165).interfaceId));

        // Test that the contract supports IGasKillerSDK
        assertTrue(sdk.supportsInterface(type(IGasKillerSDK).interfaceId));

        // Test that the contract does not support a random interface
        assertFalse(sdk.supportsInterface(0x12345678));

        // Test that the contract does not support 0xffffffff (invalid interface ID)
        assertFalse(sdk.supportsInterface(0xffffffff));
    }

    function test_externalCallVerification_Success() public {
        // Deploy a target contract with a view function
        ExternalCallTarget target = new ExternalCallTarget();
        target.setValue(12345);

        StateUpdateType[] memory types = new StateUpdateType[](0);
        bytes[] memory args = new bytes[](0);

        // Create expected external call - calling getValue() should return 12345
        bytes memory callData = abi.encodeWithSignature("getValue()");
        bytes memory expectedResult = abi.encode(uint256(12345));

        ExternalCall[] memory expectedExternalCalls = new ExternalCall[](1);
        expectedExternalCalls[0] = ExternalCall({
            target: address(target),
            callData: callData,
            expectedResult: expectedResult
        });

        // Should succeed because the actual result matches expected
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalCalls);
    }

    function test_externalCallVerification_Mismatch() public {
        // Deploy a target contract with a view function
        ExternalCallTarget target = new ExternalCallTarget();
        target.setValue(12345);

        StateUpdateType[] memory types = new StateUpdateType[](0);
        bytes[] memory args = new bytes[](0);

        // Create expected external call with wrong expected result
        bytes memory callData = abi.encodeWithSignature("getValue()");
        bytes memory wrongExpectedResult = abi.encode(uint256(99999)); // Wrong value

        ExternalCall[] memory expectedExternalCalls = new ExternalCall[](1);
        expectedExternalCalls[0] = ExternalCall({
            target: address(target),
            callData: callData,
            expectedResult: wrongExpectedResult
        });

        // Should revert because actual result (12345) != expected result (99999)
        vm.expectRevert(
            abi.encodeWithSelector(
                StateChangeHandlerLib.ExternalCallResultMismatch.selector,
                address(target),
                callData,
                wrongExpectedResult,
                abi.encode(uint256(12345))
            )
        );
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalCalls);
    }

    function test_externalCallVerification_MultipleResults() public {
        // Deploy a target contract
        ExternalCallTarget target = new ExternalCallTarget();
        target.setValue(100);
        target.setName("test");

        StateUpdateType[] memory types = new StateUpdateType[](0);
        bytes[] memory args = new bytes[](0);

        // Create multiple expected external calls
        ExternalCall[] memory expectedExternalCalls = new ExternalCall[](2);

        // First call: getValue()
        expectedExternalCalls[0] = ExternalCall({
            target: address(target),
            callData: abi.encodeWithSignature("getValue()"),
            expectedResult: abi.encode(uint256(100))
        });

        // Second call: getName()
        expectedExternalCalls[1] = ExternalCall({
            target: address(target),
            callData: abi.encodeWithSignature("getName()"),
            expectedResult: abi.encode("test")
        });

        // Should succeed because both actual results match expected
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalCalls);
    }
}

contract ExternalCallTarget {
    uint256 private _value;
    string private _name;

    function setValue(uint256 val) public {
        _value = val;
    }

    function setName(string memory name) public {
        _name = name;
    }

    function getValue() external view returns (uint256) {
        return _value;
    }

    function getName() external view returns (string memory) {
        return _name;
    }
}

contract SimpleTarget {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function revertCall() public pure {
        bytes32 _msg = "reverted";
        assembly {
            mstore(0, _msg)
            revert(0, 8)
        }
    }
}
