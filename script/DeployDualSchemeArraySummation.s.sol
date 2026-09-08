// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {DualSchemeArraySummation} from "../src/migration/examples/DualSchemeArraySummation.sol";

/// @title DeployDualSchemeArraySummation
/// @notice Deploys a DualSchemeArraySummation demo target wired to both verifiers, so it
///         settles against a BLS fleet and a Schnorr fleet alike.
/// @dev Requires `AVS_ADDRESS`, `SIG_CHECKER_ADDRESS` and `SCHNORR_STAKE_REGISTRY_ADDRESS`;
///      `ARRAY_SIZE`, `MAX_VALUE` and `ARRAY_SEED` are optional. Neither verifier is
///      deployed here. The Schnorr registry must already hold the registered operator set,
///      which the service's `setup_schnorr_operators` binary populates.
contract DeployDualSchemeArraySummation is Script {
    DualSchemeArraySummation public arraySummation;

    function setUp() public {}

    function run() public {
        address avsAddress = vm.envOr("AVS_ADDRESS", address(0));
        address sigChecker = vm.envOr("SIG_CHECKER_ADDRESS", address(0));
        address stakeRegistry = vm.envOr("SCHNORR_STAKE_REGISTRY_ADDRESS", address(0));
        uint256 arraySize = vm.envOr("ARRAY_SIZE", uint256(1000));
        uint256 maxValue = vm.envOr("MAX_VALUE", uint256(10000));
        uint256 seed = vm.envOr("ARRAY_SEED", uint256(block.timestamp));

        require(avsAddress != address(0), "AVS_ADDRESS must be set");
        require(sigChecker != address(0), "SIG_CHECKER_ADDRESS must be set");
        require(stakeRegistry != address(0), "SCHNORR_STAKE_REGISTRY_ADDRESS must be set");

        require(sigChecker.code.length > 0, "SIG_CHECKER_ADDRESS has no code");
        _validateRegistry(stakeRegistry);

        vm.startBroadcast();

        arraySummation = new DualSchemeArraySummation(avsAddress, sigChecker, stakeRegistry, arraySize, maxValue, seed);

        vm.stopBroadcast();

        console.log("DualSchemeArraySummation deployed at:", address(arraySummation));
        console.log("BLS signature checker:", sigChecker);
        console.log("Schnorr stake registry:", stakeRegistry);
        console.log("AVS Address:", avsAddress);
        console.log("Array size:", arraySize);
        console.log("Max value:", maxValue);
        console.log("Array initialized with seed:", seed);
        console.log("Actual array length:", arraySummation.getArrayLength());
        // Parseable marker for deploy automation (Helm job -> ConfigMap).
        console.log(string.concat("DEPLOYED_TARGET=", vm.toString(address(arraySummation))));
    }

    /// @notice Ensure `stakeRegistry` is a SchnorrStakeRegistry.
    /// @dev Probes `nextPossibleMutationBlock()`, which the registry exposes and the
    ///      BLS-side contracts do not.
    /// @param stakeRegistry The address the target will verify aggregate signatures against
    function _validateRegistry(address stakeRegistry) internal view {
        require(stakeRegistry.code.length > 0, "SCHNORR_STAKE_REGISTRY_ADDRESS has no code");
        (bool ok, bytes memory ret) = stakeRegistry.staticcall(abi.encodeWithSignature("nextPossibleMutationBlock()"));
        require(
            ok && ret.length >= 32,
            "SCHNORR_STAKE_REGISTRY_ADDRESS is not a SchnorrStakeRegistry (no nextPossibleMutationBlock)"
        );
    }
}
