// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {OwnableUpgradeable} from "@openzeppelin-upgrades-v5/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgrades-v5/contracts/proxy/utils/Initializable.sol";
import {GasKillerSDK} from "./GasKillerSDK.sol";

/**
 * @title GasKillerSDKOwnable
 * @notice Upgradeable GasKillerSDK with Ownable access control
 */
abstract contract GasKillerSDKOwnable is GasKillerSDK, OwnableUpgradeable {
    /**
     * @notice Initializes the contract with AVS address and BLS Signature Checker, and sets the owner
     * @param _avsAddress The address of the AVS service manager
     * @param _blsSignatureChecker The address of the BLS signature checker
     * @param _owner The address to set as the contract owner
     */
    function __GasKillerSDKOwnable_init(address _avsAddress, address _blsSignatureChecker, address _owner)
        internal
        onlyInitializing
    {
        __GasKillerSDKOwnable_init_unchained(_avsAddress, _blsSignatureChecker, _owner);
    }

    function __GasKillerSDKOwnable_init_unchained(address _avsAddress, address _blsSignatureChecker, address _owner)
        internal
        onlyInitializing
    {
        __Ownable_init_unchained(_owner);
        GasKillerSDK.__GasKillerSDK_init_unchained(_avsAddress, _blsSignatureChecker);
    }

    /**
     * @notice Disables initializers for the contract
     */
    function _disableInitializers() internal override(Initializable) {
        super._disableInitializers();
    }

    /**
     * @notice Allows the owner to set the AVS address
     * @param newAvsAddress The new AVS address
     * @dev Also updates the namespace for the contract
     */
    function setAvsAddress(address newAvsAddress) external onlyOwner {
        _setAvsAddress(newAvsAddress);
    }
}
