// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

/**
 * @title StateTracker
 * @notice A contract that tracks state transitions using a storage slot
 * @dev This contract provides functionality to track the number of state transitions
 *      that have occurred in a contract. It uses a precomputed storage slot to store
 *      the transition count.
 *
 *      The storage slot is computed as:
 *      keccak256("gasKiller.stateTracker") - 1
 *
 *      This contract is meant to be inherited by other contracts that need to track
 *      their state transitions for Gas Killer functionality.
 */
contract StateTracker {
    /**
     * @notice The precomputed storage slot for tracking state transitions
     * @dev This slot is computed as keccak256("gasKiller.stateTracker") - 1
     *      It is used to store the number of state transitions that have occurred
     */
    bytes32 internal constant STATE_TRACKER_STORAGE_LOCATION =
        0xdebfdfd5a50ad117c10898d68b5ccf0893c6b40d4f443f902e2e7646601bdeaf;

    /**
     * @notice Modifier that increments the state transition counter
     * @dev This modifier should be used on functions that modify the contract's state
     *      and need to be tracked for Gas Killer functionality.
     *
     *      The modifier:
     *      1. Loads the current transition count from storage
     *      2. Increments it by 1
     *      3. Stores the new count back to storage
     *      4. Executes the modified function
     */
    modifier trackState() {
        assembly {
            let count := sload(STATE_TRACKER_STORAGE_LOCATION)
            sstore(STATE_TRACKER_STORAGE_LOCATION, add(0x01, count))
        }
        _;
    }

    /**
     * @notice Returns the current number of state transitions
     * @return count The number of state transitions that have occurred
     * @dev This function reads the transition count directly from storage
     */
    function stateTransitionCount() public view returns (uint256 count) {
        assembly {
            count := sload(STATE_TRACKER_STORAGE_LOCATION)
        }
    }
}
