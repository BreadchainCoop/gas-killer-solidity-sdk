// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {ExternalStorageSlot} from "./interface/IGasKillerSDK.sol";

enum StateUpdateType {
    STORE,
    CALL,
    LOG0,
    LOG1,
    LOG2,
    LOG3,
    LOG4
}

library StateChangeHandlerLib {
    /// @notice Decodes and executes a series of state updates with external storage slot verification
    /// @dev This function processes an array of state updates, executing them in sequence. Each update can be one of:
    ///      - STORE: Direct storage writes using assembly
    ///      - CALL: External contract calls with value transfer
    ///      - LOG0-LOG4: Event emission with 0-4 indexed topics
    ///      Before executing any state updates, all external storage slots are verified by performing SLOAD
    ///      and comparing against the expected values from the ZK proof.
    /// @param types Array of StateUpdateType enums indicating the type of each state update operation
    /// @param args Array of ABI-encoded arguments corresponding to each operation type
    /// @param expectedExternalSlots Array of external storage slots with expected values (as proven in ZK proof)
    /// @dev types and args arrays must be equal length, with args[i] containing the encoded parameters for types[i]
    function _runStateUpdates(
        StateUpdateType[] memory types,
        bytes[] memory args,
        ExternalStorageSlot[] calldata expectedExternalSlots
    ) internal {
        require(types.length == args.length, InvalidArguments());

        // Verify all external storage slots have the expected values before executing state updates
        for (uint256 i = 0; i < expectedExternalSlots.length; i++) {
            ExternalStorageSlot calldata expectedSlot = expectedExternalSlots[i];
            bytes32 actualValue;
            address target = expectedSlot.contractAddress;
            bytes32 slot = expectedSlot.slot;

            // Perform SLOAD on the external contract's storage slot
            assembly {
                // Use extcodecopy trick to read storage from external contract
                // We use staticcall to a minimal contract that returns the storage value
                // Actually, we need to use a different approach - direct storage read only works for self
                // For external contracts, we need to call them. But we can use the SLOAD opcode
                // only on our own storage. For external storage, we need to use staticcall.

                // Build a staticcall to read storage. We'll call the target with empty calldata
                // and use the slot as the storage key. But this won't work directly.

                // The correct approach is to use extcodesize and then call a view function,
                // but since we're checking arbitrary slots, we need a different mechanism.

                // For EVM, there's no direct opcode to read another contract's storage.
                // We need to either:
                // 1. Use a helper contract that exposes storage reading
                // 2. Accept that this verification needs to be done differently

                // For now, let's use assembly to load the storage slot as if we could
                // Note: This will only work for slots in THIS contract, not external contracts
                actualValue := sload(slot)
            }

            // For external contract storage, we need to use staticcall with a view function
            // Since we can't directly read external storage, we need a different approach
            if (target != address(this)) {
                // For external contracts, we need to call a storage-reading function
                // This is a limitation - we can only verify if the contract exposes its storage
                // For now, we'll use a staticcall pattern
                bytes memory result;
                bool success;

                // Attempt to read storage using a common pattern (slot-based getter)
                // This requires the target to have a way to expose its storage
                (success, result) = target.staticcall(abi.encodeWithSignature("getStorageAt(bytes32)", slot));

                if (success && result.length >= 32) {
                    actualValue = abi.decode(result, (bytes32));
                } else {
                    // If no getter exists, we cannot verify - this is a limitation
                    // For production, you may want to require all external contracts to implement this
                    revert ExternalStorageSlotMismatch(target, slot, expectedSlot.value, bytes32(0));
                }
            }

            require(
                actualValue == expectedSlot.value,
                ExternalStorageSlotMismatch(target, slot, expectedSlot.value, actualValue)
            );
        }

        for (uint256 i = 0; i < types.length; i++) {
            StateUpdateType stateUpdateType = types[i];
            bytes memory arg = args[i];

            if (stateUpdateType == StateUpdateType.STORE) {
                (bytes32 slot, bytes32 value) = abi.decode(arg, (bytes32, bytes32));
                assembly {
                    sstore(slot, value)
                }
            } else if (stateUpdateType == StateUpdateType.CALL) {
                (
                    address target,
                    uint256 value,
                    bytes memory callargs
                ) = abi.decode(arg, (address, uint256, bytes));

                bool success;
                // TOOD: might need better gas handling
                uint256 callgas = gasleft();
                assembly {
                    success := call(callgas, target, value, add(callargs, 0x20), mload(callargs), 0, 0)
                }
                // TODO: this section needs heavy testing
                if (!success) {
                    uint256 _returndatasize;
                    assembly {
                        _returndatasize := returndatasize()
                    }
                    bytes memory revertData = new bytes(_returndatasize);
                    assembly {
                        returndatacopy(add(revertData, 0x20), 0, _returndatasize)
                    }
                    revert RevertingContext(i, target, revertData, callargs);
                }
            } else if (stateUpdateType == StateUpdateType.LOG0) {
                // NOTE: For consistency I decode an abi encoding of bytes from bytes, but technically it's redundant
                (bytes memory data) = abi.decode(arg, (bytes));
                assembly {
                    log0(add(data, 0x20), mload(data))
                }
            } else if (stateUpdateType == StateUpdateType.LOG1) {
                (bytes memory data, bytes32 topic1) = abi.decode(arg, (bytes, bytes32));
                assembly {
                    log1(add(data, 0x20), mload(data), topic1)
                }
            } else if (stateUpdateType == StateUpdateType.LOG2) {
                (bytes memory data, bytes32 topic1, bytes32 topic2) = abi.decode(arg, (bytes, bytes32, bytes32));
                assembly {
                    log2(add(data, 0x20), mload(data), topic1, topic2)
                }
            } else if (stateUpdateType == StateUpdateType.LOG3) {
                (bytes memory data, bytes32 topic1, bytes32 topic2, bytes32 topic3) =
                    abi.decode(arg, (bytes, bytes32, bytes32, bytes32));
                assembly {
                    log3(add(data, 0x20), mload(data), topic1, topic2, topic3)
                }
            } else if (stateUpdateType == StateUpdateType.LOG4) {
                (bytes memory data, bytes32 topic1, bytes32 topic2, bytes32 topic3, bytes32 topic4) =
                    abi.decode(arg, (bytes, bytes32, bytes32, bytes32, bytes32));
                assembly {
                    log4(add(data, 0x20), mload(data), topic1, topic2, topic3, topic4)
                }
            }
        }
    }

    error InvalidArguments();
    error RevertingContext(uint256 index, address target, bytes revertData, bytes callargs);
    error ExternalStorageSlotMismatch(address contractAddress, bytes32 slot, bytes32 expectedValue, bytes32 actualValue);
}
