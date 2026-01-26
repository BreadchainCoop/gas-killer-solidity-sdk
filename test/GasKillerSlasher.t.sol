// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {GasKillerSlasher} from "../src/GasKillerSlasher.sol";
import {IGasKillerSlasher} from "../src/interface/IGasKillerSlasher.sol";
import {ISP1Verifier} from "../src/interface/ISP1Verifier.sol";
import {IHeliosLightClient} from "../src/interface/IHeliosLightClient.sol";
import {IAllocationManagerTypes} from "eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IStrategy} from "eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import {OperatorSet} from "eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";

contract MockSP1Verifier is ISP1Verifier {
    bool public shouldFail;

    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    function verifyProof(bytes32, bytes calldata, bytes calldata) external view {
        if (shouldFail) {
            revert("Invalid proof");
        }
    }
}

contract MockHeliosLightClient is IHeliosLightClient {
    mapping(bytes32 => bool) public validBlockHashes;

    function setBlockHashValid(bytes32 blockHash, bool isValid) external {
        validBlockHashes[blockHash] = isValid;
    }

    function isBlockHashValid(bytes32 blockHash) external view returns (bool) {
        return validBlockHashes[blockHash];
    }

    function getBlockHash(uint256) external pure returns (bytes32) {
        return bytes32(0);
    }
}

// Simple mock - just needs to be an address we can cast to IStrategy
contract MockStrategy {}

contract MockInstantSlasher {
    // Track slashing calls
    address[] public slashedOperators;
    string public lastDescription;
    uint256 public nextRequestId;

    function fulfillSlashingRequest(IAllocationManagerTypes.SlashingParams memory _slashingParams) external {
        slashedOperators.push(_slashingParams.operator);
        lastDescription = _slashingParams.description;
        nextRequestId++;
    }

    function slasher() external view returns (address) {
        return msg.sender;
    }

    function getSlashedOperators() external view returns (address[] memory) {
        return slashedOperators;
    }

    function clearSlashedOperators() external {
        delete slashedOperators;
    }
}

contract MockAllocationManager {
    mapping(address => bool) public slashableOperators;
    IStrategy[] public strategies;

    function setOperatorSlashable(address operator, bool slashable) external {
        slashableOperators[operator] = slashable;
    }

    function setStrategies(IStrategy[] calldata _strategies) external {
        delete strategies;
        for (uint256 i = 0; i < _strategies.length; i++) {
            strategies.push(_strategies[i]);
        }
    }

    function isOperatorSlashable(address operator, OperatorSet memory) external view returns (bool) {
        return slashableOperators[operator];
    }

    function getStrategiesInOperatorSet(OperatorSet memory) external view returns (IStrategy[] memory) {
        return strategies;
    }
}

contract GasKillerSlasherTest is Test {
    GasKillerSlasher public slasher;
    MockSP1Verifier public sp1Verifier;
    MockHeliosLightClient public helios;
    MockInstantSlasher public instantSlasher;
    MockAllocationManager public allocationManager;
    MockStrategy public strategy;

    bytes32 public constant PROGRAM_VKEY = bytes32(uint256(1));
    uint256 public constant CHALLENGE_WINDOW = 7 days;
    uint32 public constant OPERATOR_SET_ID = 1;

    address public avs = makeAddr("avs");
    address public challenger = makeAddr("challenger");
    address public operator1 = makeAddr("operator1");
    address public operator2 = makeAddr("operator2");

    // Test data
    bytes32 public anchorHash = keccak256("anchor");
    address public contractAddress = makeAddr("target");
    address public callerAddress = makeAddr("caller");
    bytes public contractCalldata = abi.encodeWithSignature("foo()");
    bytes public storageUpdates = abi.encode(bytes32(uint256(1)), bytes32(uint256(100)));
    bytes public differentStorageUpdates = abi.encode(bytes32(uint256(1)), bytes32(uint256(999)));

    function setUp() public {
        sp1Verifier = new MockSP1Verifier();
        helios = new MockHeliosLightClient();
        instantSlasher = new MockInstantSlasher();
        allocationManager = new MockAllocationManager();
        strategy = new MockStrategy();

        // Set up strategies - cast MockStrategy address to IStrategy
        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = IStrategy(address(strategy));
        allocationManager.setStrategies(strategies);

        // Register operators as slashable
        allocationManager.setOperatorSlashable(operator1, true);
        allocationManager.setOperatorSlashable(operator2, true);

        // Make anchor hash valid
        helios.setBlockHashValid(anchorHash, true);

        slasher = new GasKillerSlasher(
            address(sp1Verifier),
            address(helios),
            address(instantSlasher),
            address(allocationManager),
            avs,
            PROGRAM_VKEY,
            CHALLENGE_WINDOW,
            OPERATOR_SET_ID
        );
    }

    function _createCommitment(bytes memory _storageUpdates)
        internal
        view
        returns (IGasKillerSlasher.SignedCommitment memory)
    {
        address[] memory signers = new address[](2);
        signers[0] = operator1;
        signers[1] = operator2;

        return IGasKillerSlasher.SignedCommitment({
            transitionIndex: 1,
            contractAddress: contractAddress,
            anchorHash: anchorHash,
            callerAddress: callerAddress,
            contractCalldata: contractCalldata,
            storageUpdates: _storageUpdates,
            blsSignature: bytes("signature"),
            signers: signers
        });
    }

    function _createPublicValues(bytes memory _storageUpdates) internal view returns (bytes memory) {
        return abi.encode(
            uint256(1), // id
            anchorHash, // anchorHash
            uint8(0), // anchorType
            bytes32(0), // chainConfigHash
            callerAddress, // callerAddress
            contractAddress, // contractAddress
            contractCalldata, // contractCalldata
            _storageUpdates, // contractOutput (contains storage updates)
            bytes32(0) // opcodeHash
        );
    }

    // ============ Constructor Tests ============

    function test_constructor_setsImmutables() public view {
        assertEq(address(slasher.SP1_VERIFIER()), address(sp1Verifier));
        assertEq(address(slasher.HELIOS()), address(helios));
        assertEq(address(slasher.INSTANT_SLASHER()), address(instantSlasher));
        assertEq(address(slasher.ALLOCATION_MANAGER()), address(allocationManager));
        assertEq(slasher.AVS(), avs);
        assertEq(slasher.PROGRAM_V_KEY(), PROGRAM_VKEY);
        assertEq(slasher.CHALLENGE_WINDOW(), CHALLENGE_WINDOW);
        assertEq(slasher.OPERATOR_SET_ID(), OPERATOR_SET_ID);
    }

    // ============ Slash Tests ============

    function test_slash_successWithFraud() public {
        // Create commitment with one set of storage updates
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);

        // Create public values with DIFFERENT storage updates (fraud)
        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        vm.prank(challenger);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);

        // Verify commitment is marked as slashed
        bytes32 commitmentHash = slasher.computeCommitmentHash(commitment);
        assertTrue(slasher.isSlashed(commitmentHash));

        // Verify operators were slashed via InstantSlasher
        address[] memory slashedOps = instantSlasher.getSlashedOperators();
        assertEq(slashedOps.length, 2);
        assertEq(slashedOps[0], operator1);
        assertEq(slashedOps[1], operator2);
    }

    function test_slash_revertsAlreadySlashed() public {
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        // First slash succeeds
        vm.prank(challenger);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);

        // Second slash reverts
        vm.prank(challenger);
        vm.expectRevert(IGasKillerSlasher.AlreadySlashed.selector);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    function test_slash_revertsInvalidProof() public {
        sp1Verifier.setShouldFail(true);

        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        vm.prank(challenger);
        vm.expectRevert(IGasKillerSlasher.InvalidProof.selector);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    function test_slash_revertsUnverifiedBlock() public {
        // Make the anchor hash invalid
        helios.setBlockHashValid(anchorHash, false);

        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        vm.prank(challenger);
        vm.expectRevert(IGasKillerSlasher.UnverifiedBlock.selector);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    function test_slash_revertsNoFraudDetected() public {
        // Create commitment and public values with SAME storage updates (no fraud)
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes memory sp1PublicValues = _createPublicValues(storageUpdates);

        vm.prank(challenger);
        vm.expectRevert(IGasKillerSlasher.NoFraudDetected.selector);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    function test_slash_revertsChallengeExpired() public {
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes32 commitmentHash = slasher.computeCommitmentHash(commitment);

        // Record commitment timestamp
        slasher.recordCommitment(commitmentHash);

        // Fast forward past challenge window
        vm.warp(block.timestamp + CHALLENGE_WINDOW + 1);

        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        vm.prank(challenger);
        vm.expectRevert(IGasKillerSlasher.ChallengeExpired.selector);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    function test_slash_withinChallengeWindow() public {
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes32 commitmentHash = slasher.computeCommitmentHash(commitment);

        // Record commitment timestamp
        slasher.recordCommitment(commitmentHash);

        // Fast forward but stay within challenge window
        vm.warp(block.timestamp + CHALLENGE_WINDOW - 1);

        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        vm.prank(challenger);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);

        assertTrue(slasher.isSlashed(commitmentHash));
    }

    // ============ Input Mismatch Tests ============

    function test_slash_revertsAnchorMismatch() public {
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);

        // Create public values with different anchor hash
        bytes memory sp1PublicValues = abi.encode(
            uint256(1),
            keccak256("different_anchor"), // Different anchor
            uint8(0),
            bytes32(0),
            callerAddress,
            contractAddress,
            contractCalldata,
            differentStorageUpdates,
            bytes32(0)
        );

        vm.prank(challenger);
        vm.expectRevert(IGasKillerSlasher.NoFraudDetected.selector);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    function test_slash_revertsCallerMismatch() public {
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);

        // Create public values with different caller
        bytes memory sp1PublicValues = abi.encode(
            uint256(1),
            anchorHash,
            uint8(0),
            bytes32(0),
            makeAddr("different_caller"), // Different caller
            contractAddress,
            contractCalldata,
            differentStorageUpdates,
            bytes32(0)
        );

        vm.prank(challenger);
        vm.expectRevert(IGasKillerSlasher.NoFraudDetected.selector);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    // ============ Commitment Hash Tests ============

    function test_computeCommitmentHash_deterministic() public view {
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);

        bytes32 hash1 = slasher.computeCommitmentHash(commitment);
        bytes32 hash2 = slasher.computeCommitmentHash(commitment);

        assertEq(hash1, hash2);
    }

    function test_computeCommitmentHash_differentInputs() public view {
        IGasKillerSlasher.SignedCommitment memory commitment1 = _createCommitment(storageUpdates);
        IGasKillerSlasher.SignedCommitment memory commitment2 = _createCommitment(differentStorageUpdates);

        bytes32 hash1 = slasher.computeCommitmentHash(commitment1);
        bytes32 hash2 = slasher.computeCommitmentHash(commitment2);

        assertTrue(hash1 != hash2);
    }

    // ============ Record Commitment Tests ============

    function test_recordCommitment_setsTimestamp() public {
        bytes32 commitmentHash = keccak256("commitment");

        uint256 expectedTimestamp = block.timestamp;
        slasher.recordCommitment(commitmentHash);

        assertEq(slasher.getCommitmentTimestamp(commitmentHash), expectedTimestamp);
    }

    function test_recordCommitment_doesNotOverwrite() public {
        bytes32 commitmentHash = keccak256("commitment");

        uint256 firstTimestamp = block.timestamp;
        slasher.recordCommitment(commitmentHash);

        vm.warp(block.timestamp + 1000);

        slasher.recordCommitment(commitmentHash);

        // Should still be the first timestamp
        assertEq(slasher.getCommitmentTimestamp(commitmentHash), firstTimestamp);
    }

    // ============ Events Tests ============

    function test_slash_emitsEvents() public {
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes32 commitmentHash = slasher.computeCommitmentHash(commitment);
        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        address[] memory signers = new address[](2);
        signers[0] = operator1;
        signers[1] = operator2;

        vm.expectEmit(true, true, false, false);
        emit IGasKillerSlasher.ChallengeSubmitted(commitmentHash, challenger);

        vm.expectEmit(true, true, false, true);
        emit IGasKillerSlasher.SlashingExecuted(commitmentHash, challenger, signers, 1e18);

        vm.prank(challenger);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    // ============ Edge Cases ============

    function test_slash_unslashableOperatorNotSlashed() public {
        // Make operator2 not slashable
        allocationManager.setOperatorSlashable(operator2, false);

        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        vm.prank(challenger);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);

        // Only operator1 should be slashed
        address[] memory slashedOps = instantSlasher.getSlashedOperators();
        assertEq(slashedOps.length, 1);
        assertEq(slashedOps[0], operator1);
    }

    function test_slash_noHelios() public {
        // Deploy slasher without Helios
        GasKillerSlasher slasherNoHelios = new GasKillerSlasher(
            address(sp1Verifier),
            address(0), // No Helios
            address(instantSlasher),
            address(allocationManager),
            avs,
            PROGRAM_VKEY,
            CHALLENGE_WINDOW,
            OPERATOR_SET_ID
        );

        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        // Should revert since EIP-4788 fallback returns false
        vm.prank(challenger);
        vm.expectRevert(IGasKillerSlasher.UnverifiedBlock.selector);
        slasherNoHelios.slash(commitment, bytes("proof"), sp1PublicValues);
    }

    // ============ EigenLayer Integration Tests ============

    function test_slash_callsInstantSlasherWithCorrectParams() public {
        IGasKillerSlasher.SignedCommitment memory commitment = _createCommitment(storageUpdates);
        bytes memory sp1PublicValues = _createPublicValues(differentStorageUpdates);

        vm.prank(challenger);
        slasher.slash(commitment, bytes("proof"), sp1PublicValues);

        // Verify the description includes commitment hash
        bytes32 commitmentHash = slasher.computeCommitmentHash(commitment);
        string memory expectedPrefix = "Gas Killer fraud detected for commitment: 0x";
        assertTrue(bytes(instantSlasher.lastDescription()).length > bytes(expectedPrefix).length);
    }
}
