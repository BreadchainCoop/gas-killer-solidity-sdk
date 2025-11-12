// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {Ownable} from "@openzeppelin-v5/contracts/access/Ownable.sol";
import {GasKillerSDK} from "./GasKillerSDK.sol";

/**
 * @title GasKillerSDKOwnable
 * @notice GasKillerSDK extension with Ownable access control for admin functions
 */
contract GasKillerSDKOwnable is GasKillerSDK, Ownable {
    constructor(address _avsAddress, address _blsSignatureChecker, address _owner)
        GasKillerSDK(_avsAddress, _blsSignatureChecker)
        Ownable(_owner)
    {}

    /**
     * @notice Allows the contract owner to set a new AVS address
     * @param newAvsAddress The new AVS service manager address
     * @dev Also updates the namespace for the contract
     */
    function setAvsAddress(address newAvsAddress) external onlyOwner {
        _setAvsAddress(newAvsAddress);
    }
}
