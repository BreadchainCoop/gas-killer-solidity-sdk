// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {GasKillerSDK} from "../../src/GasKillerSDK.sol";

contract GasKillerSDKExposed is GasKillerSDK {
    constructor(address _avsAddress) GasKillerSDK(_avsAddress) {}

    function stateChangeHandlerExternal(bytes calldata storageUpdates) external {
        super._stateChangeHandler(storageUpdates);
    }
}
