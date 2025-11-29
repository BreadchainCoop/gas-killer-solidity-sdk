// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {ExternalCall} from "./interface/IGasKillerSDK.sol";

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
    /// @notice Decodes and executes a series of state updates with external call verification
    /// @dev This function processes an array of state updates, executing them in sequence. Each update can be one of:
    ///      - STORE: Direct storage writes using assembly
    ///      - CALL: External contract calls with value transfer
    ///      - LOG0-LOG4: Event emission with 0-4 indexed topics
    ///      Before executing any state updates, all first-level external calls are replayed and verified
    ///      to ensure they return the same results as during the ZK proof execution.
    /// @param types Array of StateUpdateType enums indicating the type of each state update operation
    /// @param args Array of ABI-encoded arguments corresponding to each operation type
    /// @param expectedExternalCalls Array of first-level external calls with expected results (as proven in ZK proof)
    /// @dev types and args arrays must be equal length, with args[i] containing the encoded parameters for types[i]
    function _runStateUpdates(
        StateUpdateType[] memory types,
        bytes[] memory args,
        ExternalCall[] calldata expectedExternalCalls
    ) internal {
        require(types.length == args.length, InvalidArguments());

        // Verify all first-level external calls return the expected results before executing state updates
        for (uint256 i = 0; i < expectedExternalCalls.length; i++) {
            ExternalCall calldata externalCall = expectedExternalCalls[i];

            (bool success, bytes memory actualResult) = externalCall.target.staticcall(externalCall.callData);

            if (!success) {
                revert ExternalCallResultMismatch(externalCall.target, externalCall.callData, externalCall.expectedResult, actualResult);
            }

            // Compare the full return data
            if (keccak256(actualResult) != keccak256(externalCall.expectedResult)) {
                revert ExternalCallResultMismatch(externalCall.target, externalCall.callData, externalCall.expectedResult, actualResult);
            }
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
    error ExternalCallResultMismatch(address target, bytes callData, bytes expectedResult, bytes actualResult);
}
