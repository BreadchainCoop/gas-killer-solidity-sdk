// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.27;

import {IGasKillerSlasher} from "./interface/IGasKillerSlasher.sol";
import {ISP1Verifier} from "./interface/ISP1Verifier.sol";
import {IHeliosLightClient} from "./interface/IHeliosLightClient.sol";
import {IInstantSlasher} from "@eigenlayer-middleware/interfaces/IInstantSlasher.sol";
import {IAllocationManager, IAllocationManagerTypes} from "eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IStrategy} from "eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import {OperatorSet} from "eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";

/**
 * @title GasKillerSlasher
 * @notice Contract for detecting fraud and slashing malicious operators via EigenLayer
 * @dev Verifies SP1 proofs to detect incorrect storage updates and triggers EigenLayer slashing
 *      through the InstantSlasher middleware contract.
 *
 *      Slashing flow:
 *      1. Challenger calls slash() with fraud proof
 *      2. GasKillerSlasher verifies SP1 proof and detects fraud
 *      3. GasKillerSlasher calls InstantSlasher.fulfillSlashingRequest()
 *      4. InstantSlasher calls AllocationManager.slashOperator()
 *
 *      Note: This contract must be set as the authorized `slasher` in the InstantSlasher contract.
 */
contract GasKillerSlasher is IGasKillerSlasher {
    // ============ Constants ============

    /// @notice EIP-4788 beacon roots contract address
    address public constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice EIP-4788 history buffer length (~27 hours of blocks)
    uint256 public constant BEACON_ROOTS_HISTORY_BUFFER = 8191;

    /// @notice Wad amount for full slash (100%)
    uint256 public constant FULL_SLASH_WAD = 1e18;

    // ============ Immutables ============

    /// @notice The SP1 verifier contract
    ISP1Verifier public immutable SP1_VERIFIER;

    /// @notice The Helios light client contract
    IHeliosLightClient public immutable HELIOS;

    /// @notice The EigenLayer InstantSlasher contract
    IInstantSlasher public immutable INSTANT_SLASHER;

    /// @notice The EigenLayer AllocationManager contract
    IAllocationManager public immutable ALLOCATION_MANAGER;

    /// @notice The AVS address (Gas Killer service manager)
    address public immutable AVS;

    /// @notice The SP1 program verification key
    bytes32 public immutable PROGRAM_V_KEY;

    /// @notice The challenge window duration in seconds
    uint256 public immutable CHALLENGE_WINDOW;

    /// @notice The operator set ID for Gas Killer
    uint32 public immutable OPERATOR_SET_ID;

    // ============ Storage ============

    /// @notice Mapping of commitment hash to slashed status
    mapping(bytes32 => bool) private _slashed;

    /// @notice Mapping of commitment hash to application timestamp
    mapping(bytes32 => uint256) private _commitmentTimestamp;

    // ============ Constructor ============

    /**
     * @notice Initialize the slasher contract
     * @param _sp1Verifier The SP1 verifier contract address
     * @param _helios The Helios light client contract address
     * @param _instantSlasher The EigenLayer InstantSlasher contract address
     * @param _allocationManager The EigenLayer AllocationManager contract address
     * @param _avs The AVS (Gas Killer service manager) address
     * @param _programVKey The SP1 program verification key
     * @param _challengeWindow The challenge window duration in seconds
     * @param _operatorSetId The operator set ID for Gas Killer
     */
    constructor(
        address _sp1Verifier,
        address _helios,
        address _instantSlasher,
        address _allocationManager,
        address _avs,
        bytes32 _programVKey,
        uint256 _challengeWindow,
        uint32 _operatorSetId
    ) {
        SP1_VERIFIER = ISP1Verifier(_sp1Verifier);
        HELIOS = IHeliosLightClient(_helios);
        INSTANT_SLASHER = IInstantSlasher(_instantSlasher);
        ALLOCATION_MANAGER = IAllocationManager(_allocationManager);
        AVS = _avs;
        PROGRAM_V_KEY = _programVKey;
        CHALLENGE_WINDOW = _challengeWindow;
        OPERATOR_SET_ID = _operatorSetId;
    }

    // ============ External Functions ============

    /**
     * @inheritdoc IGasKillerSlasher
     */
    function slash(SignedCommitment calldata commitment, bytes calldata sp1Proof, bytes calldata sp1PublicValues)
        external
    {
        bytes32 commitmentHash = computeCommitmentHash(commitment);

        // Check if already slashed
        if (_slashed[commitmentHash]) {
            revert AlreadySlashed();
        }

        // Check challenge window (if commitment has a timestamp)
        uint256 timestamp = _commitmentTimestamp[commitmentHash];
        if (timestamp != 0 && block.timestamp > timestamp + CHALLENGE_WINDOW) {
            revert ChallengeExpired();
        }

        // Verify the SP1 proof
        _verifyProof(sp1Proof, sp1PublicValues);

        // Verify the anchor block hash
        _verifyAnchorHash(commitment.anchorHash);

        // Decode public values and detect fraud
        (bool isFraud,) = _detectFraud(commitment, sp1PublicValues);
        if (!isFraud) {
            revert NoFraudDetected();
        }

        // Mark as slashed
        _slashed[commitmentHash] = true;

        // Execute slashing for each signer via EigenLayer
        _executeSlashing(commitment.signers, commitmentHash);

        emit ChallengeSubmitted(commitmentHash, msg.sender);
        emit SlashingExecuted(commitmentHash, msg.sender, commitment.signers, FULL_SLASH_WAD);
    }

    /**
     * @inheritdoc IGasKillerSlasher
     */
    function isSlashed(bytes32 commitmentHash) external view returns (bool) {
        return _slashed[commitmentHash];
    }

    /**
     * @inheritdoc IGasKillerSlasher
     */
    function challengeWindow() external view returns (uint256) {
        return CHALLENGE_WINDOW;
    }

    /**
     * @inheritdoc IGasKillerSlasher
     */
    function programVKey() external view returns (bytes32) {
        return PROGRAM_V_KEY;
    }

    /**
     * @inheritdoc IGasKillerSlasher
     */
    function computeCommitmentHash(SignedCommitment calldata commitment) public pure returns (bytes32) {
        return sha256(
            abi.encode(
                commitment.transitionIndex,
                commitment.contractAddress,
                commitment.anchorHash,
                commitment.callerAddress,
                commitment.contractCalldata,
                commitment.storageUpdates
            )
        );
    }

    /**
     * @notice Record a commitment timestamp (called by GasKillerSDK on verifyAndUpdate)
     * @param commitmentHash The commitment hash
     */
    function recordCommitment(bytes32 commitmentHash) external {
        // Only allow recording if not already recorded
        if (_commitmentTimestamp[commitmentHash] == 0) {
            _commitmentTimestamp[commitmentHash] = block.timestamp;
        }
    }

    /**
     * @notice Get the timestamp when a commitment was applied
     * @param commitmentHash The commitment hash
     * @return The timestamp or 0 if not recorded
     */
    function getCommitmentTimestamp(bytes32 commitmentHash) external view returns (uint256) {
        return _commitmentTimestamp[commitmentHash];
    }

    // ============ Internal Functions ============

    /**
     * @notice Verify the SP1 proof
     * @param proofBytes The SP1 proof bytes
     * @param publicValues The public values
     */
    function _verifyProof(bytes calldata proofBytes, bytes calldata publicValues) internal view {
        try SP1_VERIFIER.verifyProof(PROGRAM_V_KEY, publicValues, proofBytes) {
            // Proof is valid
        } catch {
            revert InvalidProof();
        }
    }

    /**
     * @notice Verify the anchor block hash using Helios or EIP-4788
     * @param anchorHash The block hash to verify
     */
    function _verifyAnchorHash(bytes32 anchorHash) internal view {
        // First try Helios
        if (address(HELIOS) != address(0)) {
            if (HELIOS.isBlockHashValid(anchorHash)) {
                return;
            }
        }

        // Fall back to EIP-4788 for recent blocks
        if (_verifyViaEIP4788(anchorHash)) {
            return;
        }

        revert UnverifiedBlock();
    }

    /**
     * @notice Verify a block hash via EIP-4788 beacon roots
     * @param anchorHash The block hash to verify
     * @return True if the block hash is valid
     */
    function _verifyViaEIP4788(bytes32 anchorHash) internal pure returns (bool) {
        // Query the beacon roots contract for recent block roots
        // EIP-4788 stores beacon block roots, not execution block hashes
        // For simplicity, we return false here - production would need
        // proper beacon root to execution block hash mapping
        (anchorHash);
        return false;
    }

    /**
     * @notice Detect fraud by comparing signed vs proven storage updates
     * @param commitment The signed commitment
     * @param sp1PublicValues The SP1 public values
     * @return isFraud True if fraud is detected
     * @return reason Description of fraud or mismatch
     */
    function _detectFraud(SignedCommitment calldata commitment, bytes calldata sp1PublicValues)
        internal
        pure
        returns (bool isFraud, string memory reason)
    {
        ContractPublicValues memory proven = _decodePublicValues(sp1PublicValues);

        // Verify inputs match
        if (proven.anchorHash != commitment.anchorHash) {
            return (false, "Anchor mismatch - invalid challenge");
        }
        if (proven.callerAddress != commitment.callerAddress) {
            return (false, "Caller mismatch - invalid challenge");
        }
        if (proven.contractAddress != commitment.contractAddress) {
            return (false, "Contract mismatch - invalid challenge");
        }
        if (keccak256(proven.contractCalldata) != keccak256(commitment.contractCalldata)) {
            return (false, "Calldata mismatch - invalid challenge");
        }

        // Extract storage updates from proven output and compare
        bytes memory provenStorageUpdates = _extractStorageUpdates(proven.contractOutput);

        // Compare storage updates
        if (keccak256(provenStorageUpdates) != keccak256(commitment.storageUpdates)) {
            return (true, "Storage updates differ - FRAUD DETECTED");
        }

        return (false, "No fraud detected");
    }

    /**
     * @notice Decode the SP1 public values
     * @param publicValues The encoded public values
     * @return The decoded ContractPublicValues struct
     */
    function _decodePublicValues(bytes calldata publicValues) internal pure returns (ContractPublicValues memory) {
        (
            uint256 id,
            bytes32 anchorHash,
            uint8 anchorType,
            bytes32 chainConfigHash,
            address callerAddress,
            address contractAddress,
            bytes memory contractCalldata,
            bytes memory contractOutput,
            bytes32 opcodeHash
        ) = abi.decode(publicValues, (uint256, bytes32, uint8, bytes32, address, address, bytes, bytes, bytes32));

        return ContractPublicValues({
            id: id,
            anchorHash: anchorHash,
            anchorType: anchorType,
            chainConfigHash: chainConfigHash,
            callerAddress: callerAddress,
            contractAddress: contractAddress,
            contractCalldata: contractCalldata,
            contractOutput: contractOutput,
            opcodeHash: opcodeHash
        });
    }

    /**
     * @notice Extract storage updates from the contract output
     * @param contractOutput The contract execution output
     * @return The storage updates portion of the output
     */
    function _extractStorageUpdates(bytes memory contractOutput) internal pure returns (bytes memory) {
        // The contract output contains the storage updates
        // In production, this would parse the specific format from SP1 contract call
        // For now, we assume the output IS the storage updates
        return contractOutput;
    }

    /**
     * @notice Execute slashing for the given operators via EigenLayer InstantSlasher
     * @param signers Array of operator addresses to slash
     * @param commitmentHash The commitment hash for the slashing description
     */
    function _executeSlashing(address[] calldata signers, bytes32 commitmentHash) internal {
        // Get strategies from the allocation manager for the operator set
        OperatorSet memory operatorSet = OperatorSet({avs: AVS, id: OPERATOR_SET_ID});
        IStrategy[] memory strategies = ALLOCATION_MANAGER.getStrategiesInOperatorSet(operatorSet);

        // Create wads array for full slash
        uint256[] memory wadsToSlash = new uint256[](strategies.length);
        for (uint256 i = 0; i < strategies.length; i++) {
            wadsToSlash[i] = FULL_SLASH_WAD;
        }

        string memory description =
            string(abi.encodePacked("Gas Killer fraud detected for commitment: ", _bytes32ToHexString(commitmentHash)));

        // Slash each signer via InstantSlasher
        for (uint256 i = 0; i < signers.length; i++) {
            // Check if operator is slashable for this operator set
            if (ALLOCATION_MANAGER.isOperatorSlashable(signers[i], operatorSet)) {
                IAllocationManagerTypes.SlashingParams memory slashingParams = IAllocationManagerTypes.SlashingParams({
                    operator: signers[i],
                    operatorSetId: OPERATOR_SET_ID,
                    strategies: strategies,
                    wadsToSlash: wadsToSlash,
                    description: description
                });

                // Call InstantSlasher to execute the slash
                // Note: This contract must be set as the authorized `slasher` in InstantSlasher
                INSTANT_SLASHER.fulfillSlashingRequest(slashingParams);
            }
        }
    }

    /**
     * @notice Convert bytes32 to hex string
     * @param value The bytes32 value
     * @return The hex string representation
     */
    function _bytes32ToHexString(bytes32 value) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(66);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i] & 0x0f)];
        }
        return string(str);
    }
}
