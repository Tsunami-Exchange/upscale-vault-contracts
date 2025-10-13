// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockERC20
 * @dev Minimal ERC20 mock with mint functionality for testing
 */
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public immutable DECIMALS = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Constructor
     * @param n Token name
     * @param s Token symbol
     */
    constructor(string memory n, string memory s) {
        name = n;
        symbol = s;
    }

    /**
     * @dev Returns the number of decimals
     * @return The number of decimals
     */
    function decimals() external pure returns (uint8) {
        return 18;
    }

    /**
     * @dev Mints tokens to an address
     * @param to The recipient address
     * @param amount The amount to mint
     */
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    /**
     * @dev Transfers tokens
     * @param to The recipient address
     * @param amount The amount to transfer
     * @return True if successful
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "BAL_LOW");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @dev Approves spender to spend tokens
     * @param spender The spender address
     * @param amount The amount to approve
     * @return True if successful
     */
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /**
     * @dev Transfers tokens from one address to another
     * @param from The sender address
     * @param to The recipient address
     * @param amount The amount to transfer
     * @return True if successful
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "BAL_LOW");
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE_LOW");
        
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        
        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Returns the total supply (not tracked in this mock)
     * @return Always returns 0
     */
    function totalSupply() external pure returns (uint256) {
        return 0; // Not tracked in this simple mock
    }
}
