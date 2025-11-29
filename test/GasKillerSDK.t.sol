// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {IERC165} from "forge-std/interfaces/IERC165.sol";

import "../src/GasKillerSDK.sol";
import "./exposed/GasKillerSDKExposed.sol";
import {StateUpdateType} from "../src/StateChangeHandlerLib.sol";
import {StateChangeHandlerLib} from "../src/StateChangeHandlerLib.sol";
import {ExternalStorageSlot} from "../src/interface/IGasKillerSDK.sol";

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

        ExternalStorageSlot[] memory expectedExternalSlots = new ExternalStorageSlot[](0);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalSlots);

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

        ExternalStorageSlot[] memory expectedExternalSlots = new ExternalStorageSlot[](0);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalSlots);

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
        ExternalStorageSlot[] memory expectedExternalSlots = new ExternalStorageSlot[](0);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalSlots);
    }

    function test_stateChangeHandlerExternal_Log1() public {
        StateUpdateType[] memory types = new StateUpdateType[](1);
        types[0] = StateUpdateType.LOG1;

        bytes[] memory args = new bytes[](1);
        args[0] = abi.encode(bytes("log data"), keccak256("Log1(bytes)"));
        console.logBytes(args[0]);

        vm.recordLogs();

        ExternalStorageSlot[] memory expectedExternalSlots = new ExternalStorageSlot[](0);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalSlots);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics.length, 1);
        assertEq(logs[0].topics[0], keccak256("Log1(bytes)"));
        assertEq(logs[0].data, "log data");
    }

    function test_stateChangeHandlerExternal_InvalidArguments() public {
        StateUpdateType[] memory types = new StateUpdateType[](2);
        bytes[] memory args = new bytes[](1);

        ExternalStorageSlot[] memory expectedExternalSlots = new ExternalStorageSlot[](0);
        vm.expectRevert(StateChangeHandlerLib.InvalidArguments.selector);
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalSlots);
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

    function test_externalStorageSlotVerification_Success() public {
        // Deploy a target contract with a getStorageAt function
        StorageReadableTarget target = new StorageReadableTarget();
        target.setValue(12345);

        // Get the storage slot for the value (slot 0)
        bytes32 slot = bytes32(uint256(0));
        bytes32 expectedValue = bytes32(uint256(12345));

        StateUpdateType[] memory types = new StateUpdateType[](0);
        bytes[] memory args = new bytes[](0);

        // Create expected external slot with the correct value
        ExternalStorageSlot[] memory expectedExternalSlots = new ExternalStorageSlot[](1);
        expectedExternalSlots[0] = ExternalStorageSlot({
            contractAddress: address(target),
            slot: slot,
            value: expectedValue
        });

        // Should succeed because the actual storage value matches expected
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalSlots);
    }

    function test_externalStorageSlotVerification_Mismatch() public {
        // Deploy a target contract with a getStorageAt function
        StorageReadableTarget target = new StorageReadableTarget();
        target.setValue(12345);

        // Get the storage slot for the value (slot 0)
        bytes32 slot = bytes32(uint256(0));
        bytes32 wrongValue = bytes32(uint256(99999)); // Wrong value

        StateUpdateType[] memory types = new StateUpdateType[](0);
        bytes[] memory args = new bytes[](0);

        // Create expected external slot with wrong value
        ExternalStorageSlot[] memory expectedExternalSlots = new ExternalStorageSlot[](1);
        expectedExternalSlots[0] = ExternalStorageSlot({
            contractAddress: address(target),
            slot: slot,
            value: wrongValue
        });

        // Should revert because actual value (12345) != expected value (99999)
        vm.expectRevert(
            abi.encodeWithSelector(
                StateChangeHandlerLib.ExternalStorageSlotMismatch.selector,
                address(target),
                slot,
                wrongValue,
                bytes32(uint256(12345))
            )
        );
        sdk.stateChangeHandlerExternal(abi.encode(types, args), expectedExternalSlots);
    }
}

contract StorageReadableTarget {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function getStorageAt(bytes32 slot) external view returns (bytes32) {
        bytes32 result;
        assembly {
            result := sload(slot)
        }
        return result;
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
