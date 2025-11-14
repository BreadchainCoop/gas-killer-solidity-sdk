// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {GasKillerSDK} from "../../src/GasKillerSDK.sol";

contract GasKillerSDKExposed is GasKillerSDK {
    function initialize(address _avsAddress, address _blsSignatureChecker) external initializer {
        __GasKillerSDK_init(_avsAddress, _blsSignatureChecker);
    }

    function stateChangeHandlerExternal(bytes calldata storageUpdates) external {
        super._stateChangeHandler(storageUpdates);
    }
}
