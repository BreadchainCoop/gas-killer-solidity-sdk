// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

// NOTE: only relevant for alloy
interface IStateUpdateTypes {
    struct Store {
        bytes32 slot;
        bytes32 value;
    }

    struct Call {
        address target;
        uint256 value;
        bytes callargs;
    }

    struct Log0 {
        bytes data;
    }

    struct Log1 {
        bytes data;
        bytes32 topic1;
    }

    struct Log2 {
        bytes data;
        bytes32 topic1;
        bytes32 topic2;
    }

    struct Log3 {
        bytes data;
        bytes32 topic1;
        bytes32 topic2;
        bytes32 topic3;
    }

    struct Log4 {
        bytes data;
        bytes32 topic1;
        bytes32 topic2;
        bytes32 topic3;
        bytes32 topic4;
    }
}
