// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {OptimizedHashing} from "./OptimizedHashing.sol";
import {TransientStorage} from "./TransientStorage.sol";
import {IDeterministicVault} from "./interfaces/IDeterministicVault.sol";
import {PaymentWallet} from "./PaymentWallet.sol";

/**
 * @title DeterministicVault
 * @dev A vault that acts as its own factory for deterministic payment wallets
 * and manages payments through them, allowing withdrawals via signed intents
 * @notice Optimized for Cancun EVM with transient storage and MCOPY support
 * @notice Requires Solidity 0.8.24+ and Cancun-compatible EVM
 */
contract DeterministicVault is IDeterministicVault, Initializable, OwnableUpgradeable, ReentrancyGuardUpgradeable, UUPSUpgradeable {
    using SafeERC20 for IERC20;
    using OptimizedHashing for *;
    using TransientStorage for bytes32;

    mapping(address => bool) public tokenWhitelist;                     // ERC20 whitelist
    mapping(address => uint256) public totalBalances;                   // token => total tracked
    mapping(bytes32 => mapping(address => uint256)) public byPayment;   // paymentId => token => amount

    address public intentSigner;                                        // signer for off-chain intents
    mapping(address => uint256) public nonces;                           // per-beneficiary nonces

    // EIP-712 domain
    bytes32 private _DOMAIN_SEPARATOR;
    uint256 private _CACHED_CHAIN_ID;
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _WITHDRAW_TYPEHASH =
        keccak256("WithdrawIntent(address beneficiary,address token,uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 private constant _NAME_HASH = keccak256(bytes("DeterministicVault"));
    bytes32 private constant _VERSION_HASH = keccak256(bytes("1"));

    // Gas optimization: Pre-compute init code hash for CREATE2
    bytes32 private _INIT_CODE_HASH;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Prevent the implementation contract from being initialized directly.
        // See OpenZeppelin upgrades: lock the implementation.
        _disableInitializers();
    }

    /**
     * @dev Initializer function (replaces constructor)
     */
    function initialize() public initializer {
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();

        _CACHED_CHAIN_ID = block.chainid;
        _DOMAIN_SEPARATOR = keccak256(abi.encode(
            _EIP712_DOMAIN_TYPEHASH,
            _NAME_HASH,
            _VERSION_HASH,
            block.chainid,
            address(this)
        ));

        // Pre-compute init code hash for gas optimization
        bytes memory initCode = type(PaymentWallet).creationCode;
        _INIT_CODE_HASH = OptimizedHashing.hashBytes(initCode);
    }

    /**
     * @dev Modifier to ensure only the payment wallet can call certain functions
     */
    modifier onlyWallet(bytes32 paymentId) {
        require(msg.sender == walletAddress(paymentId), "ONLY_PAYMENT_WALLET");
        _;
    }

    /* --------------------- Factory functionality --------------------- */

    /**
     * @dev Converts a UUID string to a payment ID
     * @param uuid The UUID string
     * @return The payment ID
     */
    function paymentIdFromUuid(string calldata uuid) external pure returns (bytes32) {
        return OptimizedHashing.hashString(string(uuid));
    }

    /**
     * @dev Returns the init code for the payment wallet (gas optimized)
     * @return The init code
     */
    function _initCode() internal pure returns (bytes memory) {
        return type(PaymentWallet).creationCode;
    }

    /**
     * @dev Returns the pre-computed init code hash (gas optimized)
     * @return The init code hash
     */
    function _initCodeHash() internal view returns (bytes32) {
        return _INIT_CODE_HASH;
    }

    /**
     * @dev Returns the deterministic wallet address for a given payment ID
     * @param paymentId The payment ID
     * @return predicted The wallet address
     */
    function walletAddress(bytes32 paymentId) public view returns (address predicted) {
        // Gas optimization: Use pre-computed hash instead of recalculating
        bytes32 _data = OptimizedHashing.hashCreate2(address(this), paymentId, _INIT_CODE_HASH);
        return address(uint160(uint256(_data)));
    }

    /**
     * @dev Returns the wallet address for a given UUID
     * @param uuid The UUID string
     * @return The wallet address
     */
    function walletAddressFromUuid(string calldata uuid) external view returns (address) {
        return walletAddress(OptimizedHashing.hashString(string(uuid)));
    }

    /**
     * @dev Deploys a wallet for a given payment ID if not already deployed
     * @param paymentId The payment ID
     * @return w The wallet address
     */
    function _deploy(bytes32 paymentId) internal returns (address w) {
        address predicted = walletAddress(paymentId);
        if (predicted.code.length > 0) return predicted; // already deployed

        // Sanity: ensure cached init code hash matches current creationCode; this prevents silent mismatches.
        // If PaymentWallet bytecode changed without updating _INIT_CODE_HASH, fail early.
        bytes32 currentHash = OptimizedHashing.hashBytes(_initCode());
        require(_INIT_CODE_HASH == currentHash, "INIT_CODE_HASH_MISMATCH");

        // Gas optimization: Generate init code efficiently
        bytes memory code = _initCode();
        assembly {
            let len := mload(code)
            let ptr := add(code, 0x20)
            w := create2(0, ptr, len, paymentId)
            if iszero(w) { revert(0, 0) }
        }
        require(w == predicted, "ADDR_MISMATCH");
        PaymentWallet(payable(w)).initialize(address(this));
    }

    /**
     * @dev LAZY entrypoint (anyone): deploy if needed, then sweep to vault.
     * @param paymentId bytes32 id (e.g., keccak256(uuid))
     * @param token ERC20 to sweep (single token); ETH is always swept
     * @param payer optional attribution (can be address(0) if unknown)
     * @return wallet The wallet address
     */
    function sweep(
        bytes32 paymentId,
        address token,
        address payer
    ) external returns (address wallet) {
        wallet = _deploy(paymentId);
        // initiate sweep to this vault
        _initiateLazySweep(paymentId, payer, token);
        // Note: Swept event is emitted in onLazySweep with actual amounts
    }

    /**
     * @dev Direct payment to the vault (push payment)
     * @notice For ERC20 tokens, requires exact-amount approval. Do not approve MAX_UINT256.
     * @notice The approved amount must exactly match the `amount` parameter (respecting token decimals).
     * @param paymentId The payment ID to credit
     * @param token The token address (address(0) for ETH)
     * @param amount The token amount (for ETH, must match msg.value)
     */
    function payDirect(bytes32 paymentId, address token, uint256 amount) external payable {
        require(paymentId != bytes32(0), "ZERO_PAYMENT_ID");

        if (token == address(0)) {
            // ETH payment
            uint256 ethValue = msg.value; // Gas optimization: cache msg.value
            require(ethValue > 0, "NO_ETH_SENT");
            require(amount == ethValue, "ETH_AMOUNT_MISMATCH");

            totalBalances[address(0)] += ethValue;
            byPayment[paymentId][address(0)] += ethValue;

            emit DirectPayment(paymentId, msg.sender, address(0), ethValue);
            emit Deposited(paymentId, msg.sender, address(0), ethValue);
        } else {
            // ERC20 payment
            require(msg.value == 0, "NO_ETH_FOR_TOKEN_PAYMENT");
            require(amount > 0, "ZERO_AMOUNT");
            require(tokenWhitelist[token], "TOKEN_NOT_WHITELISTED");

            // Enforce exact-amount approval to prevent MAX_UINT256 approvals
            // This reduces Blockaid warnings by ensuring users only approve what they intend to pay
            uint256 allowance = IERC20(token).allowance(msg.sender, address(this));
            require(allowance >= amount, "INSUFFICIENT_ALLOWANCE");
            require(allowance <= amount, "EXCESSIVE_ALLOWANCE"); // Reject MAX_UINT256-style approvals

            // Transfer tokens from sender to vault
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

            totalBalances[token] += amount;
            byPayment[paymentId][token] += amount;

            emit DirectPayment(paymentId, msg.sender, token, amount);
            emit Deposited(paymentId, msg.sender, token, amount);
        }
    }

    /**
     * @dev Direct payment to the vault using EIP-2612 permit (gasless approval)
     * @notice This function allows payment without a separate approval transaction.
     * @notice The permit signature must be signed by the owner of the tokens.
     * @notice Token must support EIP-2612 permit functionality.
     * @param paymentId The payment ID to credit
     * @param token The token address (must support permit, cannot be address(0))
     * @param amount The token amount to transfer
     * @param deadline The deadline for the permit signature
     * @param v The recovery byte of the permit signature
     * @param r The r component of the permit signature
     * @param s The s component of the permit signature
     */
    function payDirectWithPermit(
        bytes32 paymentId,
        address token,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        require(paymentId != bytes32(0), "ZERO_PAYMENT_ID");
        require(token != address(0), "TOKEN_0_FORBIDDEN");
        require(amount > 0, "ZERO_AMOUNT");
        require(tokenWhitelist[token], "TOKEN_NOT_WHITELISTED");
        require(block.timestamp <= deadline, "PERMIT_EXPIRED");

        // Use try-catch for permit to handle tokens that don't support it gracefully
        // Following OpenZeppelin's recommended pattern for permit usage
        try IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s) {
            // Permit succeeded, proceed with transfer
        } catch {
            revert("PERMIT_FAILED");
        }

        // Transfer tokens from sender to vault using the permit approval
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        totalBalances[token] += amount;
        byPayment[paymentId][token] += amount;

        emit DirectPayment(paymentId, msg.sender, token, amount);
        emit Deposited(paymentId, msg.sender, token, amount);
    }

    /* --------------------- Admin config --------------------- */

    /**
     * @dev Sets the whitelist status for a token
     * @param token The token address
     * @param allowed Whether the token is allowed
     */
    function setWhitelist(address token, bool allowed) external onlyOwner {
        require(token != address(0), "TOKEN_0_FORBIDDEN"); // ETH is always allowed; whitelist only ERC20s here
        tokenWhitelist[token] = allowed;
        emit WhitelistSet(token, allowed);
    }

    /**
     * @dev Sets the intent signer address
     * @param signer The signer address
     */
    function setIntentSigner(address signer) external onlyOwner {
        require(signer != address(0), "ZERO_SIGNER");
        intentSigner = signer;
        emit IntentSignerSet(signer);
    }

    /* --------------------- Lazy sweep (Vault-initiated) --------------------- */

    /**
     * @dev Initiates a pull-style sweep from the wallet to this vault.
     * Vault calls the wallet, which transfers the single `token` and all ETH back to the vault,
     * then calls back `onLazySweep(...)` with exact amounts.
     * @param paymentId The payment ID
     * @param payer The payer address
     * @param token The token to sweep
     */
    function _initiateLazySweep(bytes32 paymentId, address payer, address token) internal {
        address wallet = walletAddress(paymentId);
        // Call wallet to sweep funds into us; the wallet will callback `onLazySweep`
        PaymentWallet(payable(wallet)).sweepToVault(paymentId, payer, payable(address(this)), token);
    }

    /**
     * @dev Callback from the wallet after it has transferred ERC20 and is forwarding ETH.
     * Accounts balances per token and per paymentId.
     * @param paymentId The payment ID
     * @param payer The payer address
     * @param token The token address
     * @param tokenAmount The token amount transferred
     */
    function onLazySweep(
        bytes32 paymentId,
        address payer,
        address token,
        uint256 tokenAmount
    ) external payable onlyWallet(paymentId) nonReentrant {
        // Cancun optimization: Use transient storage for temp values
        uint256 nativeAmt = msg.value;
        address wallet = msg.sender;

        // Store in transient storage for potential reuse in same transaction
        TransientStorage.TEMP_ADDRESS_SLOT.setAddress(wallet);
        TransientStorage.TEMP_AMOUNT_SLOT.setUint256(nativeAmt);
        TransientStorage.TEMP_TOKEN_SLOT.setAddress(token);

        if (nativeAmt > 0) {
            // Gas optimization: Cache zero address
            address zeroAddr = address(0);
            totalBalances[zeroAddr] += nativeAmt;
            byPayment[paymentId][zeroAddr] += nativeAmt;
            emit Deposited(paymentId, payer, zeroAddr, nativeAmt);
        }

        // Prevent silent acceptance of tokens that are not whitelisted.
        // If a token is not whitelisted, fail early so the PaymentWallet's
        // sweep does not succeed in transferring untracked tokens.
        if (token != address(0) && tokenAmount > 0) {
            require(tokenWhitelist[token], "TOKEN_NOT_WHITELISTED_ON_SWEEP");
            totalBalances[token] += tokenAmount;
            byPayment[paymentId][token] += tokenAmount;
            emit Deposited(paymentId, payer, token, tokenAmount);
        }

        emit Swept(paymentId, wallet, token, nativeAmt, tokenAmount);
    }

    /* --------------------- Admin ops --------------------- */

    /**
     * @dev Admin function to transfer tokens/ETH from the vault
     * @notice This is an administrative function for emergency fund recovery or authorized transfers.
     * @notice All admin transfers are tracked and emit events for transparency.
     * @param token The token address (address(0) for ETH)
     * @param to The recipient address
     * @param amount The amount to transfer
     */
    function adminTransfer(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        require(to != address(0), "ZERO_TO");

        // Gas optimization: Cache storage read
        uint256 currentBalance = totalBalances[token];
        require(currentBalance >= amount, "INSUFFICIENT_TRACKED");
        totalBalances[token] = currentBalance - amount;

        if (token == address(0)) {
            (bool ok, ) = to.call{value: amount}("");
            require(ok, "NATIVE_SEND_FAIL");
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
        emit AdminTransfer(token, to, amount);
    }

    /* --------------------- User withdrawals via signed intent --------------------- */

    /**
     * @dev Returns the domain separator for EIP-712
     * @return The domain separator
     */
    function domainSeparator() public view returns (bytes32) {
        return block.chainid == _CACHED_CHAIN_ID ? _DOMAIN_SEPARATOR
            : keccak256(abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _NAME_HASH,
                _VERSION_HASH,
                block.chainid,
                address(this)
            ));
    }

    /**
     * @dev Withdraws tokens/ETH using a signed intent
     * @param beneficiary The beneficiary address
     * @param token The token address (address(0) for ETH)
     * @param amount The amount to withdraw
     * @param deadline The deadline for the intent
     * @param signature The signature
     */
    function withdrawWithIntent(
        address beneficiary,
        address token,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        require(beneficiary != address(0), "ZERO_BENEF");
        require(block.timestamp <= deadline, "EXPIRED");

        // Gas optimization: Cache storage reads
        uint256 nonce = nonces[beneficiary];
        address signer = intentSigner;

        bytes32 structHash = keccak256(abi.encode(
            _WITHDRAW_TYPEHASH,
            beneficiary,
            token,
            amount,
            nonce,
            deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        require(ECDSA.recover(digest, signature) == signer, "BAD_INTENT_SIG");

        // Gas optimization: Cache storage read
        uint256 currentBalance = totalBalances[token];
        require(currentBalance >= amount, "INSUFFICIENT_TRACKED");
        totalBalances[token] = currentBalance - amount;
        nonces[beneficiary] = nonce + 1;

        if (token == address(0)) {
            (bool ok, ) = beneficiary.call{value: amount}("");
            require(ok, "NATIVE_SEND_FAIL");
        } else {
            IERC20(token).safeTransfer(beneficiary, amount);
        }
        emit Withdrawn(beneficiary, token, amount, nonce);
    }

    /**
     * @dev Direct withdrawal by owner (multisig/timelock recommended)
     * @notice This function allows the owner to withdraw funds directly without signatures.
     * @notice WARNING: Requires owner (multisig/timelock recommended). Do not grant single EOA direct withdrawal power.
     * @notice The intentSigner should only sign off-chain intents; actual withdrawals should go through owner/multisig.
     * @param beneficiary The beneficiary address
     * @param token The token address (address(0) for ETH)
     * @param amount The amount to withdraw
     */
    function withdrawDirect(address beneficiary, address token, uint256 amount) external onlyOwner nonReentrant {
        // msg.sender is owner (multisig/timelock recommended)
        require(beneficiary != address(0), "ZERO_BENEF");
        require(amount > 0, "ZERO_AMOUNT");

        // Gas optimization: Cache storage read
        uint256 currentBalance = totalBalances[token];
        require(currentBalance >= amount, "INSUFFICIENT_TRACKED");
        totalBalances[token] = currentBalance - amount;

        if (token == address(0)) {
            (bool ok, ) = beneficiary.call{value: amount}("");
            require(ok, "NATIVE_SEND_FAIL");
        } else {
            IERC20(token).safeTransfer(beneficiary, amount);
        }

        emit DirectWithdraw(msg.sender, beneficiary, token, amount);
    }

    /* --------------------- Receive (discouraged) --------------------- */

    /**
     * @dev Fallback function to receive ETH
     */
    receive() external payable {
        // Gas optimization: Cache msg.value
        uint256 ethValue = msg.value;
        totalBalances[address(0)] += ethValue;
        emit Deposited(bytes32(0), msg.sender, address(0), ethValue);
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
     * {upgradeTo} and {upgradeToAndCall}.
     */
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}
