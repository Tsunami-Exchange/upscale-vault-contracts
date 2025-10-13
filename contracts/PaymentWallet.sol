// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title PaymentWallet
 * @dev Ultra-minimal payment wallet for maximum gas efficiency
 * Removes interface inheritance and unnecessary abstractions for optimal bytecode size
 */
contract PaymentWallet is Initializable {
    using SafeERC20 for IERC20;

    address public FACTORY;
    bool public swept;

    constructor() {}

    /**
     * @dev Initializer function (replaces constructor)
     * @param factory_ The factory address
     */
    function initialize(address factory_) external initializer {
        FACTORY = factory_;
    }

    function drainToVault(
        bytes32 paymentId,
        address payer,
        address payable vault,
        address token
    ) external {
        require(msg.sender == vault && vault == FACTORY, "ONLY_VAULT_FACTORY");
        require(!swept, "ALREADY_SWEPT");
        swept = true;

        uint256 tokenAmt;
        if (token != address(0)) {
            tokenAmt = IERC20(token).balanceOf(address(this));
            if (tokenAmt > 0) {
                IERC20(token).safeTransfer(vault, tokenAmt);
            }
        }

        // Direct callback without interface dependency
        uint256 ethBalance = address(this).balance;
        bytes memory callData = abi.encodeWithSignature(
            "onLazySweep(bytes32,address,address,uint256)",
            paymentId,
            payer,
            token,
            tokenAmt
        );
        
        (bool success,) = vault.call{value: ethBalance}(callData);
        require(success, "CALLBACK_FAILED");
    }

    receive() external payable {}

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
