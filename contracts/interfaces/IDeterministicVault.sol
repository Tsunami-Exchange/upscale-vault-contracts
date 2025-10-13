// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IDeterministicVault
 * @dev Interface for the DeterministicVault contract which also acts as a factory
 */
interface IDeterministicVault {
    /**
     * @dev Events
     */
    event WhitelistSet(address indexed token, bool allowed);
    event IntentSignerSet(address indexed signer);
    event Deposited(bytes32 indexed paymentId, address indexed payer, address indexed token, uint256 amount);
    event DirectPayment(bytes32 indexed paymentId, address indexed payer, address indexed token, uint256 amount);
    event Swept(bytes32 indexed paymentId, address wallet, address indexed token, uint256 nativeAmt, uint256 tokenAmt);
    event Withdrawn(address indexed to, address indexed token, uint256 amount, uint256 nonce);
    event DirectWithdraw(address indexed signer, address indexed beneficiary, address indexed token, uint256 amount);
    event AdminCall(address indexed to, uint256 value, bytes data, bytes result);
    event AdminTransfer(address indexed token, address indexed to, uint256 amount);

    /**
     * @dev Factory functionality
     */
    function paymentIdFromUuid(string calldata uuid) external pure returns (bytes32);
    function walletAddress(bytes32 paymentId) external view returns (address);
    function walletAddressFromUuid(string calldata uuid) external view returns (address);
    function sweep(bytes32 paymentId, address token, address payer) external returns (address wallet);
    function payDirect(bytes32 paymentId, address token, uint256 amount) external payable;

    /**
     * @dev Configuration functions
     */
    function setWhitelist(address token, bool allowed) external;
    function setIntentSigner(address signer) external;

    /**
     * @dev State query functions
     */
    function tokenWhitelist(address token) external view returns (bool);
    function totalBalances(address token) external view returns (uint256);
    function byPayment(bytes32 paymentId, address token) external view returns (uint256);
    function intentSigner() external view returns (address);
    function nonces(address beneficiary) external view returns (uint256);
    function domainSeparator() external view returns (bytes32);

    /**
     * @dev Sweep functionality
     */
    function onLazySweep(
        bytes32 paymentId,
        address payer,
        address token,
        uint256 tokenAmount
    ) external payable;

    /**
     * @dev Admin functions
     */
    function adminTransfer(address token, address to, uint256 amount) external;
    function adminCall(address to, uint256 value, bytes calldata data) external returns (bytes memory);

    /**
     * @dev User withdrawal functions
     */
    function withdrawWithIntent(
        address beneficiary,
        address token,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) external;
    function withdrawDirect(address beneficiary, address token, uint256 amount) external;
}