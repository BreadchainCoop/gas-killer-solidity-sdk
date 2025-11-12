// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {GasKillerSDK} from "./GasKillerSDK.sol";

/**
 * @title GasKillerSDKOwnable
 * @notice Upgradeable GasKillerSDK with Ownable access control
 */
abstract contract GasKillerSDKOwnable is GasKillerSDK, OwnableUpgradeable {
    /// @notice Initializes the contract with AVS address and BLS Signature Checker, and sets the owner
    /// @param _avsAddress The address of the AVS service manager
    /// @param _blsSignatureChecker The address of the BLS signature checker
    /// @param _owner The address to set as the contract owner
    function initialize(address _avsAddress, address _blsSignatureChecker, address _owner) public virtual initializer {
        __Ownable_init();
        _transferOwnership(_owner);
        GasKillerSDK.initialize(_avsAddress, _blsSignatureChecker);
    }

    /**
     * @dev Example: Restricts setting AVS address to only owner.
     * If you want owner-only admin functions, you can add them like this:
     */
    function setAvsAddress(address newAvsAddress) external onlyOwner {
        _setAvsAddress(newAvsAddress);
    }

    /// @notice Disables initializers for the contract
    function _disableInitializers() internal override(Initializable) {
        super._disableInitializers();
    }
}
