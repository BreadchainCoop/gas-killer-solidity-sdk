// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

/**
 * @title IGasKillerSlasher
 * @notice Interface for the Gas Killer slashing contract
 * @dev Enables fraud detection and slashing of malicious operators
 */
interface IGasKillerSlasher {
    // ============ Structs ============

    /**
     * @notice A signed commitment from the aggregate network
     * @param transitionIndex Sequential counter for state transitions
     * @param contractAddress The target contract address
     * @param anchorHash Block hash for state anchoring
     * @param callerAddress The caller address (msg.sender for the call)
     * @param contractCalldata Full calldata with arguments
     * @param storageUpdates Claimed storage changes
     * @param blsSignature The aggregate BLS signature
     * @param signers Array of operator addresses who signed
     */
    struct SignedCommitment {
        uint256 transitionIndex;
        address contractAddress;
        bytes32 anchorHash;
        address callerAddress;
        bytes contractCalldata;
        bytes storageUpdates;
        bytes blsSignature;
        address[] signers;
    }

    /**
     * @notice Public values from SP1 proof (ContractPublicValuesWithTrace)
     * @param id Proof identifier
     * @param anchorHash Block hash used for execution
     * @param anchorType Type of anchor (execution/beacon)
     * @param chainConfigHash Hash of chain configuration
     * @param callerAddress The caller address
     * @param contractAddress The contract address
     * @param contractCalldata The calldata used
     * @param contractOutput The output from execution
     * @param opcodeHash Hash of state-modifying opcodes
     */
    struct ContractPublicValues {
        uint256 id;
        bytes32 anchorHash;
        uint8 anchorType;
        bytes32 chainConfigHash;
        address callerAddress;
        address contractAddress;
        bytes contractCalldata;
        bytes contractOutput;
        bytes32 opcodeHash;
    }

    // ============ Events ============

    /**
     * @notice Emitted when slashing is executed
     * @param commitmentHash Hash of the slashed commitment
     * @param challenger Address of the challenger who submitted the proof
     * @param slashedOperators Array of operators who were slashed
     * @param slashAmount Amount slashed per operator
     */
    event SlashingExecuted(
        bytes32 indexed commitmentHash,
        address indexed challenger,
        address[] slashedOperators,
        uint256 slashAmount
    );

    /**
     * @notice Emitted when a challenge is submitted
     * @param commitmentHash Hash of the challenged commitment
     * @param challenger Address of the challenger
     */
    event ChallengeSubmitted(bytes32 indexed commitmentHash, address indexed challenger);

    // ============ Errors ============

    /// @notice Thrown when the SP1 proof is invalid
    error InvalidProof();

    /// @notice Thrown when the anchor block hash cannot be verified
    error UnverifiedBlock();

    /// @notice Thrown when inputs don't match the commitment
    error InputMismatch();

    /// @notice Thrown when no fraud is detected
    error NoFraudDetected();

    /// @notice Thrown when the challenge window has expired
    error ChallengeExpired();

    /// @notice Thrown when the commitment has already been slashed
    error AlreadySlashed();

    /// @notice Thrown when the BLS signature is invalid
    error InvalidBLSSignature();

    /// @notice Thrown when called by an unauthorized address
    error Unauthorized();

    // ============ External Functions ============

    /**
     * @notice Submit a slashing proof for a fraudulent commitment
     * @param commitment The original signed commitment
     * @param sp1Proof The SP1 PLONK proof bytes
     * @param sp1PublicValues The SP1 public values (ContractPublicValuesWithTrace)
     */
    function slash(
        SignedCommitment calldata commitment,
        bytes calldata sp1Proof,
        bytes calldata sp1PublicValues
    ) external;

    /**
     * @notice Check if a commitment has been slashed
     * @param commitmentHash The hash of the commitment
     * @return True if the commitment has been slashed
     */
    function isSlashed(bytes32 commitmentHash) external view returns (bool);

    /**
     * @notice Get the challenge window duration
     * @return The challenge window in seconds
     */
    function challengeWindow() external view returns (uint256);

    /**
     * @notice Get the SP1 program verification key
     * @return The verification key
     */
    function programVKey() external view returns (bytes32);

    /**
     * @notice Compute the commitment hash
     * @param commitment The signed commitment
     * @return The sha256 hash of the commitment
     */
    function computeCommitmentHash(SignedCommitment calldata commitment)
        external
        pure
        returns (bytes32);
}
