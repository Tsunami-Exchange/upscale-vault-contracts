// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IPaymentWalletV1
 * @dev Interface for the upgradeable PaymentWallet contract
 */
interface IPaymentWalletV1 {
    /**
     * @dev Initialization
     */
    function initialize(address factory_) external;

    /**
     * @dev State query functions
     */
    function FACTORY() external view returns (address);
    function swept() external view returns (bool);

    /**
     * @dev Core functionality
     */
    function sweepToVault(
        bytes32 paymentId,
        address payer,
        address payable vault,
        address token
    ) external;
}
