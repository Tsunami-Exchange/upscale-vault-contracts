// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Receiver
 * @dev Mock receiver for adminCall/adminTransfer tests
 */
contract Receiver {
    uint256 public x;
    event GotEth(address indexed from, uint256 amount);

    /**
     * @dev Sets a value and optionally receives ETH
     * @param v The value to set
     */
    function setX(uint256 v) external payable {
        x = v;
        if (msg.value > 0) emit GotEth(msg.sender, msg.value);
    }
}

/**
 * @title RevertingReceiver
 * @dev Mock receiver that always reverts
 */
contract RevertingReceiver {
    fallback() external payable { 
        revert("REVERT_ALWAYS"); 
    }
    
    receive() external payable { 
        revert("REVERT_ALWAYS"); 
    }
}
