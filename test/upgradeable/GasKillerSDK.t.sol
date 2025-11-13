// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {
    ITransparentUpgradeableProxy,
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {GasKillerSDK} from "../../src/upgradeable/GasKillerSDK.sol";

// Minimal concrete V1 impl
contract GasKillerSDKV1 is GasKillerSDK {
    function initialize(address _avsAddress, address _blsSignatureChecker) external initializer {
        __GasKillerSDK_init(_avsAddress, _blsSignatureChecker);
    }

    function version() public pure returns (string memory) {
        return "V1";
    }
}

// V2 test implementation that inherits the real contract and adds a new method
contract GasKillerSDKV2 is GasKillerSDK {
    function version() public pure returns (string memory) {
        return "V2";
    }
}

contract UpgradeableGasKillerSDKTest is Test {
    ITransparentUpgradeableProxy public proxy;
    ProxyAdmin public admin;
    GasKillerSDKV1 public v1;
    GasKillerSDKV2 public v2;

    address public avs = address(0xA11CE);
    address public bls = address(0xB105);

    function setUp() public {
        admin = new ProxyAdmin();
        GasKillerSDKV1 logicV1 = new GasKillerSDKV1();
        proxy = ITransparentUpgradeableProxy(
            address(
                new TransparentUpgradeableProxy(
                    address(logicV1), address(admin), abi.encodeWithSignature("initialize(address,address)", avs, bls)
                )
            )
        );
        v1 = GasKillerSDKV1(address(proxy));
    }

    function test_canReadV1Version() public {
        // Initial storage should be set
        assertEq(v1.getAvsAddress(), avs);
        assertEq(v1.getBlsSignatureChecker(), bls);
        bytes memory expectedNs = abi.encodePacked(avs, "gaskiller");
        assertEq(keccak256(v1.getNamespace()), keccak256(expectedNs));
        assertEq(v1.version(), "V1");
    }

    function test_UpgradeToV2() public {
        GasKillerSDKV2 logicV2 = new GasKillerSDKV2();

        // Upgrade the proxy to V2 logic via ProxyAdmin (transparent proxy pattern)
        admin.upgrade(proxy, address(logicV2));

        // Cast proxy to V2 interface
        v2 = GasKillerSDKV2(address(proxy));

        // Storage should remain
        assertEq(v2.getAvsAddress(), avs);
        assertEq(v2.getBlsSignatureChecker(), bls);
        bytes memory expectedNs = abi.encodePacked(avs, "gaskiller");
        assertEq(keccak256(v2.getNamespace()), keccak256(expectedNs));

        // Check that the version is updated
        assertEq(v2.version(), "V2");
    }
}
