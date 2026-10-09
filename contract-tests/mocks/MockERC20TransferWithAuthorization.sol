// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20TransferWithAuthorization} from "../../contracts/interfaces/IERC20TransferWithAuthorization.sol";

/**
 * @title MockERC20TransferWithAuthorization
 * @dev Mock ERC20 token with EIP-3009 transferWithAuthorization functionality for testing
 */
contract MockERC20TransferWithAuthorization is ERC20, IERC20TransferWithAuthorization {
    using ECDSA for bytes32;

    // EIP-712 domain separator
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(bytes32 => bool) public authorizationStates;

    /**
     * @dev Constructor
     * @param name Token name
     * @param symbol Token symbol
     */
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    /**
     * @dev Mints tokens to an address
     * @param to The recipient address
     * @param amount The amount to mint
     */
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

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
    ) external override {
        require(value > 0, "ZERO_VALUE");
        require(block.timestamp >= validAfter, "AUTHORIZATION_NOT_YET_VALID");
        require(block.timestamp < validBefore, "AUTHORIZATION_EXPIRED");
        
        bytes32 authorizationHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, authorizationHash)
        );
        
        address signer = digest.recover(v, r, s);
        require(signer == from, "INVALID_SIGNATURE");
        
        bytes32 authorizationState = keccak256(abi.encodePacked(from, nonce));
        require(!authorizationStates[authorizationState], "AUTHORIZATION_ALREADY_USED");
        authorizationStates[authorizationState] = true;
        
        _transfer(from, to, value);
    }
}

