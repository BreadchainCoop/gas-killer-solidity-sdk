// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {
    ITransparentUpgradeableProxy,
    TransparentUpgradeableProxy
} from "@openzeppelin-v5/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin-v5/contracts/proxy/transparent/ProxyAdmin.sol";
import {GasKillerSDK} from "../../src/upgradeable/GasKillerSDK.sol";
import {GasKillerSDKOwnable} from "../../src/upgradeable/GasKillerSDKOwnable.sol";

// Minimal concrete V1 impl (non-ownable)
contract GasKillerSDKOwnableV1 is GasKillerSDK {
    function initialize(address _avsAddress, address _blsSignatureChecker) external initializer {
        __GasKillerSDK_init(_avsAddress, _blsSignatureChecker);
    }
}

// V2 test implementation that inherits the real contract and adds a new method
contract GasKillerSDKOwnableV2 is GasKillerSDKOwnable {
    // Reinitializer called during upgrade to set the owner
    function initializeV2(address _owner) external reinitializer(2) {
        __Ownable_init(_owner);
    }
}

contract UpgradeableGasKillerSDKTest is Test {
    ITransparentUpgradeableProxy public proxy;
    ProxyAdmin public admin;
    GasKillerSDKOwnableV1 public v1;
    GasKillerSDKOwnableV2 public v2;

    address public owner = address(this);
    address public avs = address(0xA11CE);
    address public bls = address(0xB105);

    function setUp() public {
        GasKillerSDKOwnableV1 logicV1 = new GasKillerSDKOwnableV1();
        proxy = ITransparentUpgradeableProxy(
            address(
                new TransparentUpgradeableProxy(
                    address(logicV1), owner, abi.encodeWithSignature("initialize(address,address)", avs, bls)
                )
            )
        );
        // Discover the ProxyAdmin that the proxy deployed (read ERC-1967 admin slot)
        bytes32 ADMIN_SLOT = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
        address proxyAdminAddr = address(uint160(uint256(vm.load(address(proxy), ADMIN_SLOT))));
        admin = ProxyAdmin(proxyAdminAddr);
        v1 = GasKillerSDKOwnableV1(address(proxy));
    }

    function test_canReadV1Version() public {
        // Initial storage should be set
        assertEq(v1.getAvsAddress(), avs);
        assertEq(v1.getBlsSignatureChecker(), bls);
        bytes memory expectedNs = abi.encodePacked(avs, "gaskiller");
        assertEq(keccak256(v1.getNamespace()), keccak256(expectedNs));
    }

    function test_UpgradeToV2_and_PreserveStorage() public {
        GasKillerSDKOwnableV2 logicV2 = new GasKillerSDKOwnableV2();

        // Upgrade the proxy to V2 logic via ProxyAdmin (transparent proxy pattern)
        // Call the V2 reinitializer to set the owner
        admin.upgradeAndCall(proxy, address(logicV2), abi.encodeWithSignature("initializeV2(address)", owner));

        // Cast proxy to V2 interface
        v2 = GasKillerSDKOwnableV2(address(proxy));

        // Storage should remain
        assertEq(v2.getAvsAddress(), avs);
        assertEq(v2.getBlsSignatureChecker(), bls);
        bytes memory expectedNs = abi.encodePacked(avs, "gaskiller");
        assertEq(keccak256(v2.getNamespace()), keccak256(expectedNs));

        // Check that the owner is set
        assertEq(v2.owner(), owner);
    }
}
