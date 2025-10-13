// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title TransientStorage
 * @dev Library for utilizing Cancun's transient storage (EIP-1153)
 * @notice Transient storage is cheaper than storage and resets after each transaction
 */
library TransientStorage {
    
    /**
     * @dev Sets a value in transient storage
     * @param slot The storage slot
     * @param value The value to store
     */
    function tstore(bytes32 slot, bytes32 value) internal {
        assembly {
            tstore(slot, value)
        }
    }
    
    /**
     * @dev Gets a value from transient storage
     * @param slot The storage slot
     * @return value The stored value
     */
    function tload(bytes32 slot) internal view returns (bytes32 value) {
        assembly {
            value := tload(slot)
        }
    }
    
    /**
     * @dev Sets an address in transient storage
     * @param slot The storage slot
     * @param value The address to store
     */
    function setAddress(bytes32 slot, address value) internal {
        assembly {
            tstore(slot, value)
        }
    }
    
    /**
     * @dev Gets an address from transient storage
     * @param slot The storage slot
     * @return value The stored address
     */
    function getAddress(bytes32 slot) internal view returns (address value) {
        assembly {
            value := tload(slot)
        }
    }
    
    /**
     * @dev Sets a uint256 in transient storage
     * @param slot The storage slot
     * @param value The uint256 to store
     */
    function setUint256(bytes32 slot, uint256 value) internal {
        assembly {
            tstore(slot, value)
        }
    }
    
    /**
     * @dev Gets a uint256 from transient storage
     * @param slot The storage slot
     * @return value The stored uint256
     */
    function getUint256(bytes32 slot) internal view returns (uint256 value) {
        assembly {
            value := tload(slot)
        }
    }
    
    /**
     * @dev Sets a boolean in transient storage
     * @param slot The storage slot
     * @param value The boolean to store
     */
    function setBool(bytes32 slot, bool value) internal {
        assembly {
            tstore(slot, value)
        }
    }
    
    /**
     * @dev Gets a boolean from transient storage
     * @param slot The storage slot
     * @return value The stored boolean
     */
    function getBool(bytes32 slot) internal view returns (bool value) {
        assembly {
            value := tload(slot)
        }
    }
    
    // Standard transient storage slots for common use cases
    bytes32 internal constant REENTRANCY_GUARD_SLOT = keccak256("TransientStorage.ReentrancyGuard");
    bytes32 internal constant TEMP_ADDRESS_SLOT = keccak256("TransientStorage.TempAddress");
    bytes32 internal constant TEMP_AMOUNT_SLOT = keccak256("TransientStorage.TempAmount");
    bytes32 internal constant TEMP_TOKEN_SLOT = keccak256("TransientStorage.TempToken");
}
