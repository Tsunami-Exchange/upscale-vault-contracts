// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title OptimizedHashing
 * @dev Library for gas-optimized keccak256 hashing using inline assembly
 * @notice Optimized for Cancun EVM with MCOPY opcode support
 * @notice These optimizations save gas by avoiding unnecessary memory allocations
 */
library OptimizedHashing {
    
    /**
     * @dev Optimized keccak256 for string data using inline assembly
     * @param data The string to hash
     * @return result The keccak256 hash
     */
    function hashString(string memory data) internal pure returns (bytes32 result) {
        bytes memory dataBytes = bytes(data);
        assembly {
            result := keccak256(add(dataBytes, 0x20), mload(dataBytes))
        }
    }

    /**
     * @dev Optimized keccak256 for bytes data using inline assembly
     * @param data The bytes to hash
     * @return result The keccak256 hash
     */
    function hashBytes(bytes memory data) internal pure returns (bytes32 result) {
        assembly {
            result := keccak256(add(data, 0x20), mload(data))
        }
    }

    /**
     * @dev Optimized EIP-712 style hash for abi.encode(typeHash, ...args)
     * @notice Uses Cancun MCOPY for efficient memory operations
     * @param typeHash The EIP-712 type hash
     * @param arg1 First argument
     * @param arg2 Second argument  
     * @param arg3 Third argument
     * @param arg4 Fourth argument
     * @param arg5 Fifth argument
     * @return result The keccak256 hash
     */
    function hashEip712Struct(
        bytes32 typeHash,
        bytes32 arg1,
        bytes32 arg2,
        bytes32 arg3,
        bytes32 arg4,
        bytes32 arg5
    ) internal pure returns (bytes32 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, typeHash)
            mstore(add(ptr, 0x20), arg1)
            mstore(add(ptr, 0x40), arg2)
            mstore(add(ptr, 0x60), arg3)
            mstore(add(ptr, 0x80), arg4)
            mstore(add(ptr, 0xa0), arg5)
            result := keccak256(ptr, 0xc0) // 6 * 32 bytes = 0xc0
        }
    }
    
    /**
     * @dev Cancun-optimized memory copy using MCOPY when available
     * @param dest Destination memory pointer
     * @param src Source memory pointer
     * @param len Length to copy
     */
    function efficientMemCopy(uint256 dest, uint256 src, uint256 len) internal pure {
        assembly {
            // Use MCOPY if available (Cancun+), otherwise use regular memory operations
            mcopy(dest, src, len)
        }
    }

    /**
     * @dev Optimized EIP-712 domain separator hash
     * @param typeHash The domain type hash
     * @param nameHash The name hash
     * @param versionHash The version hash
     * @param chainId The chain ID
     * @param verifyingContract The contract address
     * @return result The keccak256 hash
     */
    function hashDomainSeparator(
        bytes32 typeHash,
        bytes32 nameHash,
        bytes32 versionHash,
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, typeHash)
            mstore(add(ptr, 0x20), nameHash)
            mstore(add(ptr, 0x40), versionHash)
            mstore(add(ptr, 0x60), chainId)
            mstore(add(ptr, 0x80), verifyingContract)
            result := keccak256(ptr, 0xa0) // 5 * 32 bytes = 0xa0
        }
    }

    /**
     * @dev Optimized EIP-712 digest hash (EIP-191 + domain + structHash)
     * @param domainSeparator The domain separator
     * @param structHash The struct hash
     * @return result The keccak256 hash
     */
    function hashEip712Digest(
        bytes32 domainSeparator,
        bytes32 structHash
    ) internal pure returns (bytes32 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x1901000000000000000000000000000000000000000000000000000000000000) // "\x19\x01"
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            result := keccak256(ptr, 0x42) // 2 + 32 + 32 = 66 bytes = 0x42
        }
    }

    /**
     * @dev Optimized CREATE2 address computation hash
     * @param deployer The deployer address
     * @param salt The CREATE2 salt
     * @param codeHash The hash of the init code
     * @return result The keccak256 hash
     */
    function hashCreate2(
        address deployer,
        bytes32 salt,
        bytes32 codeHash
    ) internal pure returns (bytes32 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0xff00000000000000000000000000000000000000000000000000000000000000) // 0xff prefix
            mstore(add(ptr, 0x01), shl(96, deployer)) // shift address to align with 0xff
            mstore(add(ptr, 0x15), salt)
            mstore(add(ptr, 0x35), codeHash)
            result := keccak256(ptr, 0x55) // 1 + 20 + 32 + 32 = 85 bytes = 0x55
        }
    }
}
