// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IERC20TransferWithAuthorization
 * @dev Interface for EIP-3009 transferWithAuthorization functionality
 * @notice This interface defines the transferWithAuthorization function from EIP-3009
 */
interface IERC20TransferWithAuthorization {
    /**
     * @dev Returns the EIP-712 domain separator
     * @return The domain separator
     */
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /**
     * @dev Transfers tokens using an authorization signed by the token holder
     * @param from The address from which tokens are transferred
     * @param to The address to which tokens are transferred
     * @param value The amount of tokens to transfer
     * @param validAfter The timestamp after which the authorization is valid
     * @param validBefore The timestamp before which the authorization is valid
     * @param nonce A unique nonce to prevent replay attacks
     * @param v The recovery byte of the signature
     * @param r The r component of the signature
     * @param s The s component of the signature
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

