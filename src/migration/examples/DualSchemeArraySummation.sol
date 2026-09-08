// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DualSchemeGasKillerSDK} from "../DualSchemeGasKillerSDK.sol";

/// @title DualSchemeArraySummation
/// @notice Migration-period twin of `ArraySummation` and `SchnorrArraySummation`: the same
///         array/sum semantics, inheriting `DualSchemeGasKillerSDK` so it settles under
///         either verification scheme.
/// @dev The constructor is the part to copy into an integration: it wires both verifiers.
contract DualSchemeArraySummation is DualSchemeGasKillerSDK {
    /// @notice Thrown when constructor arguments would produce an unusable contract
    error InvalidConfiguration();

    /// @notice Emitted whenever a new sum is computed and stored
    /// @param newSum The newly computed sum
    /// @param timestamp The block timestamp at the time of computation
    event SumCalculated(uint256 newSum, uint256 timestamp);

    /// @notice Emitted once during construction after the array is populated
    /// @param size The number of elements initialised in the array
    event ArrayInitialized(uint256 size);

    /// @notice Number of elements in `values`; fixed at construction
    uint256 public immutable arraySize;

    /// @notice Upper bound (exclusive) for randomly generated array element values
    uint256 public immutable maxValue;

    /// @notice The most recently computed sum of selected array elements
    uint256 public currentSum;

    /// @notice The underlying array of pseudorandom values
    uint256[] public values;

    /// @notice Deploy a new DualSchemeArraySummation with both verifiers wired
    /// @dev Reverts `InvalidConfiguration` unless both verifier addresses are set.
    /// @param _avsAddress The AVS service manager address this contract is scoped to
    /// @param _blsSigChecker The BLS signature checker contract address
    /// @param _schnorrStakeRegistry The Schnorr stake registry verifying aggregate quorums
    /// @param _arraySize Number of elements to generate; must be > 0
    /// @param _maxValue Exclusive upper bound for element values; must be > 0
    /// @param _seed Seed for pseudorandom generation; 0 falls back to `block.timestamp`
    constructor(
        address _avsAddress,
        address _blsSigChecker,
        address _schnorrStakeRegistry,
        uint256 _arraySize,
        uint256 _maxValue,
        uint256 _seed
    ) {
        if (
            _avsAddress == address(0) || _blsSigChecker == address(0) || _schnorrStakeRegistry == address(0)
                || _arraySize == 0 || _maxValue == 0
        ) {
            revert InvalidConfiguration();
        }

        _setAvsAddress(_avsAddress);
        _setBlsSignatureChecker(_blsSigChecker);
        _setSchnorrRegistry(_schnorrStakeRegistry);

        arraySize = _arraySize;
        maxValue = _maxValue;

        _initializeArray(_seed);
    }

    /// @notice Populate `values` with `arraySize` pseudorandom entries bounded by `maxValue`
    /// @param _seed Entropy source; falls back to `block.timestamp` when 0
    function _initializeArray(uint256 _seed) private {
        if (_seed == 0) {
            _seed = block.timestamp;
        }

        uint256 hashedSeed = uint256(keccak256(abi.encode(_seed)));
        for (uint256 i = 0; i < arraySize; ++i) {
            values.push(uint256(keccak256(abi.encode(hashedSeed, i))) % maxValue);
        }

        emit ArrayInitialized(arraySize);
    }

    /// @notice Calculate the sum of specified array elements and record the state transition
    /// @dev Pass an empty `indexes` array to sum all elements
    /// @param indexes Zero-based positions in `values` to include in the sum
    function sum(uint256[] calldata indexes) public trackState {
        _calculateSum(indexes);
    }

    /// @notice Compute the sum of the specified elements and store it in `currentSum`
    /// @param indexes Zero-based positions to sum; sums the full array when empty
    function _calculateSum(uint256[] calldata indexes) internal {
        uint256 total = 0;

        if (indexes.length == 0) {
            // If no indexes provided, sum all elements
            uint256 length = values.length;
            for (uint256 i = 0; i < length; ++i) {
                total += values[i];
            }
        } else {
            // Sum only specified indexes
            uint256 valuesLength = values.length;
            uint256 indexesLength = indexes.length;
            for (uint256 i = 0; i < indexesLength; ++i) {
                require(indexes[i] < valuesLength, "Index out of bounds");
                total += values[indexes[i]];
            }
        }

        currentSum = total;
        emit SumCalculated(total, block.timestamp);
    }

    /// @notice Return the value at a specific array index
    /// @param index Zero-based position in `values`
    /// @return The element stored at `index`
    function getArrayElement(uint256 index) public view returns (uint256) {
        require(index < values.length, "Index out of bounds");
        return values[index];
    }

    /// @notice Return the number of elements in `values`
    /// @return The length of the array
    function getArrayLength() public view returns (uint256) {
        return values.length;
    }

    /// @notice Return a memory copy of the full `values` array
    /// @return The entire array of stored values
    function getFullArray() public view returns (uint256[] memory) {
        return values;
    }

    /// @notice Overwrite a single array element and record the state transition
    /// @param index Zero-based position in `values` to update
    /// @param newValue Replacement value to store at `index`
    function setArrayElement(uint256 index, uint256 newValue) public trackState {
        require(index < values.length, "Index out of bounds");
        values[index] = newValue;
    }

    /// @notice Clear the array and reinitialise it with a new seed, recording the state transition
    /// @param _seed Entropy source for regeneration; 0 falls back to `block.timestamp`
    function resetArray(uint256 _seed) public trackState {
        delete values;
        _initializeArray(_seed);
    }
}
