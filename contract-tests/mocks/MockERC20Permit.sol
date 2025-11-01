// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockERC20Permit
 * @dev Mock ERC20 token with EIP-2612 permit functionality for testing
 */
contract MockERC20Permit is ERC20Permit {
    /**
     * @dev Constructor
     * @param name Token name
     * @param symbol Token symbol
     */
    constructor(string memory name, string memory symbol) ERC20Permit(name) ERC20(name, symbol) {}

    /**
     * @dev Mints tokens to an address
     * @param to The recipient address
     * @param amount The amount to mint
     */
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

