// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IPaymentWallet
 * @dev Interface for the PaymentWallet contract
 */
interface IPaymentWallet {
    /**
     * @dev Returns the factory address
     * @return The factory address
     */
    function FACTORY() external view returns (address); // solhint-disable-line func-name-mixedcase

    /**
     * @dev Returns whether the wallet has been swept
     * @return True if swept, false otherwise
     */
    function swept() external view returns (bool);

    /**
     * @dev Sweeps tokens and ETH from the wallet to the vault
     * @param paymentId The payment ID
     * @param payer The payer address
     * @param vault The vault address
     * @param token The token to sweep (address(0) to skip token sweep, only ETH)
     */
    function sweepToVault(
        bytes32 paymentId,
        address payer,
        address payable vault,
        address token
    ) external;
}
