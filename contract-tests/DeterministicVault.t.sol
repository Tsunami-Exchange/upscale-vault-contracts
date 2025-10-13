// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {DeterministicVault} from "../contracts/DeterministicVault.sol";
import {PaymentWallet} from "../contracts/PaymentWallet.sol";
import {IDeterministicVault} from "../contracts/interfaces/IDeterministicVault.sol";
import {IPaymentWallet} from "../contracts/interfaces/IPaymentWallet.sol";

import {MockERC20} from "./mocks/MockERC20.sol";
import {Receiver, RevertingReceiver} from "./mocks/TestReceivers.sol";

/**
 * @title DeterministicVaultTest
 * @dev Test suite for the DeterministicVault system (vault acts as its own factory)
 */
contract DeterministicVaultTest is Test {
    DeterministicVault vault;
    MockERC20 tokenA;
    MockERC20 tokenB;
    Receiver recv;
    RevertingReceiver badRecv;

    // test actors
    address admin = makeAddr("admin");
    address alice = makeAddr("alice");
    address bob   = makeAddr("bob");

    // signer keypair for EIP-712 intents
    uint256 signerPk;
    address signerAddr;

    function setUp() public {
        vault = new DeterministicVault();
        vm.prank(admin);
        vault.initialize();

        tokenA = new MockERC20("TokenA","TKA");
        tokenB = new MockERC20("TokenB","TKB");
        recv = new Receiver();
        badRecv = new RevertingReceiver();

        // configure signer
        signerPk = 0xA11CE; // arbitrary
        signerAddr = vm.addr(signerPk);

        vm.prank(admin);
        vault.setIntentSigner(signerAddr);

        // whitelist TokenA only
        vm.prank(admin);
        vault.setWhitelist(address(tokenA), true);
    }

    /* ───────────────────── Helpers ───────────────────── */

    function _uuid(string memory s) internal pure returns (bytes32) {
        return keccak256(bytes(s));
    }

    function _fundEth(address who, uint256 amt) internal {
        vm.deal(who, amt);
    }

    function _signWithdraw(
        address beneficiary,
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        // keccak256("WithdrawIntent(address beneficiary,address token,uint256 amount,uint256 nonce,uint256 deadline)")
        bytes32 typeHash = keccak256(
            "WithdrawIntent(address beneficiary,address token,uint256 amount,uint256 nonce,uint256 deadline)"
        );
        bytes32 structHash = keccak256(abi.encode(typeHash, beneficiary, token, amount, nonce, deadline));
        bytes32 ds = IDeterministicVault(payable(address(vault))).domainSeparator();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", ds, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    /* ───────────────────── Core: deterministic address + lazy deploy + sweep (ETH only) ───────────────────── */

    function test_LazyDeployAndSweep_ETHOnly() public {
        bytes32 pid = _uuid("invoice-eth-1");
        address predicted = vault.walletAddress(pid);
        assertEq(predicted.code.length, 0, "wallet should not exist yet");

        // fund predicted address with ETH pre-deploy
        uint256 ethAmt = 3 ether;
        _fundEth(alice, ethAmt);
        vm.prank(alice);
        (bool ok,) = predicted.call{value: ethAmt}("");
        assertTrue(ok);

        // lazy sweep with token=address(0)
        vm.prank(alice);
        address wallet = vault.sweep(pid, address(0), alice);

        assertEq(wallet, predicted, "created wallet address mismatch");
        assertGt(wallet.code.length, 0, "wallet must be deployed");

        // accounted in vault
        uint256 tEth = vault.totalBalances(address(0));
        assertEq(tEth, ethAmt, "vault total ETH mismatch");
        assertEq(vault.byPayment(pid, address(0)), ethAmt, "per-payment ETH mismatch");

        // wallet should be marked swept
        assertTrue(PaymentWallet(payable(wallet)).swept(), "swept flag not set");
    }

    /* ───────────────────── Lazy deploy + sweep (whitelisted ERC20 + ETH) ───────────────────── */

    function test_LazyDeployAndSweep_TokenA_And_ETH() public {
        bytes32 pid = _uuid("invoice-erc20-1");
        address predicted = vault.walletAddress(pid);

        // Pre-fund wallet (pre-deploy) with 1 ETH and 1,000 TokenA
        _fundEth(bob, 1 ether);
        vm.prank(bob);
        (bool ok,) = predicted.call{value: 1 ether}("");
        assertTrue(ok);

        tokenA.mint(predicted, 1_000e18);
        assertEq(tokenA.balanceOf(predicted), 1_000e18);

        // Sweep specifying TokenA (whitelisted)
        vm.startPrank(bob);
        vault.sweep(pid, address(tokenA), bob);
        vm.stopPrank();

        // Accounting: ETH + TokenA booked for pid
        assertEq(vault.byPayment(pid, address(0)), 1 ether);
        assertEq(vault.byPayment(pid, address(tokenA)), 1_000e18);

        // Totals reflect both
        assertEq(vault.totalBalances(address(0)), 1 ether);
        assertEq(vault.totalBalances(address(tokenA)), 1_000e18);

        // Vault holds the actual assets
        assertEq(payable(address(vault)).balance, 1 ether);
        assertEq(tokenA.balanceOf(payable(address(vault))), 1_000e18);
    }

    /* ───────────────────── Non-whitelisted token is transferred-in but NOT accounted ───────────────────── */

    function test_Sweep_NonWhitelistedToken_NotAccountedButHeld() public {
        bytes32 pid = _uuid("invoice-nonwl-1");
        address predicted = vault.walletAddress(pid);

        tokenB.mint(predicted, 777e18);
        assertEq(tokenB.balanceOf(predicted), 777e18);

        // Sweep specifying TokenB (NOT whitelisted)
        vault.sweep(pid, address(tokenB), alice);

        // Not accounted
        assertEq(vault.byPayment(pid, address(tokenB)), 0);
        assertEq(vault.totalBalances(address(tokenB)), 0);

        // But vault actually holds the tokens
        assertEq(tokenB.balanceOf(payable(address(vault))), 777e18);

        // adminTransfer cannot move untracked tokens (reverts on INSUFFICIENT_TRACKED)
        vm.prank(admin);
        vm.expectRevert(bytes("INSUFFICIENT_TRACKED"));
        vault.adminTransfer(address(tokenB), alice, 100e18);

        // But adminCall can call token.transfer(...) to move raw balance out
        bytes memory data = abi.encodeWithSelector(MockERC20.transfer.selector, alice, 200e18);
        vm.prank(admin);
        vault.adminCall(address(tokenB), 0, data);
        assertEq(tokenB.balanceOf(alice), 200e18);
        assertEq(tokenB.balanceOf(payable(address(vault))), 577e18);
    }

    /* ───────────────────── Only-one-time drain enforced ───────────────────── */

    function test_ReSweepSamePayment_RevertsDueToWalletGuard() public {
        bytes32 pid = _uuid("invoice-once-1");
        address predicted = vault.walletAddress(pid);

        _fundEth(alice, 2 ether);
        vm.prank(alice);
        (bool ok,) = predicted.call{value: 2 ether}("");
        assertTrue(ok);

        // First sweep: OK
        vault.sweep(pid, address(0), alice);
        assertEq(vault.totalBalances(address(0)), 2 ether);

        // Re-sweep: vault asks wallet to drain, but wallet already swept -> revert
        vm.expectRevert(bytes("ALREADY_SWEPT"));
        vault.sweep(pid, address(0), alice);
    }

    /* ───────────────────── EIP-712 Withdrawals (ETH) ───────────────────── */

    function test_WithdrawWithIntent_ETH_SingleUseNonce() public {
        // prepare balance: 1 ETH
        bytes32 pid = _uuid("invoice-withdraw-eth");
        address predicted = vault.walletAddress(pid);
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = predicted.call{value: 1 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);
        assertEq(payable(address(vault)).balance, 1 ether);

        address beneficiary = bob;
        uint256 beforeBal = beneficiary.balance;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;

        bytes memory sig = _signWithdraw(beneficiary, address(0), 0.6 ether, nonce, deadline);

        // Execute withdrawal
        vm.prank(alice);
        vault.withdrawWithIntent(beneficiary, address(0), 0.6 ether, deadline, sig);

        assertEq(beneficiary.balance, beforeBal + 0.6 ether);
        assertEq(vault.totalBalances(address(0)), 0.4 ether);
        assertEq(vault.nonces(beneficiary), nonce + 1);

        // Replay with same signature should fail due to nonce changed
        vm.expectRevert();
        vault.withdrawWithIntent(beneficiary, address(0), 0.6 ether, deadline, sig);
    }

    function test_WithdrawWithIntent_ERC20() public {
        // balance: 500 TKA (whitelisted)
        bytes32 pid = _uuid("invoice-withdraw-erc20");
        address predicted = vault.walletAddress(pid);
        tokenA.mint(predicted, 500e18);
        vault.sweep(pid, address(tokenA), address(0));
        assertEq(tokenA.balanceOf(payable(address(vault))), 500e18);
        assertEq(vault.totalBalances(address(tokenA)), 500e18);

        address beneficiary = alice;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _signWithdraw(beneficiary, address(tokenA), 120e18, nonce, deadline);

        vault.withdrawWithIntent(beneficiary, address(tokenA), 120e18, deadline, sig);
        assertEq(tokenA.balanceOf(beneficiary), 120e18);
        assertEq(vault.totalBalances(address(tokenA)), 380e18);
        assertEq(vault.nonces(beneficiary), nonce + 1);
    }

    function test_WithdrawWithIntent_BadSigner_Reverts() public {
        // seed some ETH
        bytes32 pid = _uuid("invoice-badsig");
        address predicted = vault.walletAddress(pid);
        _fundEth(alice, 0.5 ether);
        vm.prank(alice);
        (bool ok,) = predicted.call{value: 0.5 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        // produce signature with a DIFFERENT key
        uint256 otherPk = 0xB0B;
        address beneficiary = alice;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;

        // build digest using vault domain
        bytes32 typeHash = keccak256(
            "WithdrawIntent(address beneficiary,address token,uint256 amount,uint256 nonce,uint256 deadline)"
        );
        bytes32 structHash = keccak256(abi.encode(typeHash, beneficiary, address(0), 0.2 ether, nonce, deadline));
        bytes32 ds = vault.domainSeparator();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", ds, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherPk, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(bytes("BAD_INTENT_SIG"));
        vault.withdrawWithIntent(beneficiary, address(0), 0.2 ether, deadline, badSig);
    }

    function test_WithdrawWithIntent_Expired_Reverts() public {
        // seed
        bytes32 pid = _uuid("invoice-expired");
        address predicted = vault.walletAddress(pid);
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = predicted.call{value: 1 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        address beneficiary = alice;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp; // expires NOW
        bytes memory sig = _signWithdraw(beneficiary, address(0), 0.1 ether, nonce, deadline);

        vm.warp(block.timestamp + 1); // now expired
        vm.expectRevert(bytes("EXPIRED"));
        vault.withdrawWithIntent(beneficiary, address(0), 0.1 ether, deadline, sig);
    }

    function test_WithdrawWithIntent_InsufficientTracked_Reverts() public {
        // No funds for tokenB
        address beneficiary = alice;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _signWithdraw(beneficiary, address(tokenB), 1e18, nonce, deadline);

        vm.expectRevert(bytes("INSUFFICIENT_TRACKED"));
        vault.withdrawWithIntent(beneficiary, address(tokenB), 1e18, deadline, sig);
    }

    /* ───────────────────── Admin ops: transfer and call (success and failure) ───────────────────── */

    function test_AdminTransfer_ETH() public {
        // seed 2 ETH
        bytes32 pid = _uuid("invoice-admin-eth");
        address predicted = vault.walletAddress(pid);
        _fundEth(alice, 2 ether);
        vm.prank(alice);
        (bool ok,) = predicted.call{value: 2 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);
        assertEq(payable(address(vault)).balance, 2 ether);

        uint256 before = bob.balance;
        vm.prank(admin);
        vault.adminTransfer(address(0), bob, 1.25 ether);
        assertEq(bob.balance, before + 1.25 ether);
        assertEq(vault.totalBalances(address(0)), 0.75 ether);
    }

    function test_AdminTransfer_ERC20() public {
        // seed 1000 TKA
        bytes32 pid = _uuid("invoice-admin-erc20");
        address predicted = vault.walletAddress(pid);
        tokenA.mint(predicted, 1000e18);
        vault.sweep(pid, address(tokenA), alice);

        vm.prank(admin);
        vault.adminTransfer(address(tokenA), bob, 320e18);
        assertEq(tokenA.balanceOf(bob), 320e18);
        assertEq(vault.totalBalances(address(tokenA)), 680e18);
    }

    function test_AdminCall_SetsStateAndSendsETH() public {
        // seed ETH
        bytes32 pid = _uuid("invoice-admincall");
        address predicted = vault.walletAddress(pid);
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = predicted.call{value: 1 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        bytes memory data = abi.encodeWithSelector(Receiver.setX.selector, 42);
        vm.prank(admin);
        vault.adminCall(address(recv), 0.4 ether, data);

        assertEq(recv.x(), 42);
        assertEq(payable(address(vault)).balance, 0.6 ether);
    }

    function test_AdminCall_RevertsOnFailure() public {
        bytes memory data = hex"deadbeef";
        vm.prank(admin);
        vm.expectRevert(bytes("ADMIN_CALL_FAIL"));
        vault.adminCall(address(badRecv), 0, data);
    }

    function test_AdminTransfer_RevertsOnNativeSendFail() public {
        // seed ETH
        bytes32 pid = _uuid("invoice-sendfail");
        address predicted = vault.walletAddress(pid);
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = predicted.call{value: 1 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        vm.prank(admin);
        vm.expectRevert(bytes("NATIVE_SEND_FAIL"));
        vault.adminTransfer(address(0), address(badRecv), 0.25 ether);
    }

    /* ───────────────────── Access control & guards ───────────────────── */

    function test_OnlyOwner_Modifiers() public {
        // setWhitelist non-owner
        vm.expectRevert();
        vault.setWhitelist(address(tokenB), true);

        // setIntentSigner non-owner
        vm.expectRevert();
        vault.setIntentSigner(bob);

        // adminTransfer non-owner
        vm.expectRevert();
        vault.adminTransfer(address(0), bob, 0);

        // adminCall non-owner
        vm.expectRevert();
        vault.adminCall(address(this), 0, "");
    }

    function test_Whitelist_ZeroAddressForbidden() public {
        vm.prank(admin);
        vm.expectRevert(bytes("TOKEN_0_FORBIDDEN"));
        vault.setWhitelist(address(0), true);
    }

    function test_OnLazySweep_OnlyWallet() public {
        bytes32 pid = _uuid("invoice-onlywallet");
        // Try to call onLazySweep directly from EOA (not allowed)
        vm.expectRevert(bytes("ONLY_PAYMENT_WALLET"));
        DeterministicVault(payable(payable(address(vault)))).onLazySweep(pid, alice, address(0), 0);
    }

    function test_Wallet_DrainToVault_OnlyVault() public {
        bytes32 pid = _uuid("invoice-walletguard");
        address wallet = vault.sweep(pid, address(0), alice);
        // second sweep will revert on ALREADY_SWEPT; but try to call drain directly first (only vault)
        vm.expectRevert(bytes("ONLY_VAULT_FACTORY"));
        IPaymentWallet(wallet).drainToVault(pid, alice, payable(address(vault)), address(0));
    }

    /* ───────────────────── Direct Payment Tests ───────────────────── */

    function test_PayDirect_ETH_Success() public {
        bytes32 pid = _uuid("direct-payment-eth");
        uint256 ethAmount = 1.5 ether;

        _fundEth(alice, ethAmount);
        vm.prank(alice);
        vault.payDirect{value: ethAmount}(pid, address(0), ethAmount);

        // Check balances
        assertEq(vault.totalBalances(address(0)), ethAmount);
        assertEq(vault.byPayment(pid, address(0)), ethAmount);
        assertEq(payable(address(vault)).balance, ethAmount);
    }

    function test_PayDirect_ERC20_Success() public {
        bytes32 pid = _uuid("direct-payment-erc20");
        uint256 tokenAmount = 500e18;

        // Mint and approve tokens
        tokenA.mint(alice, tokenAmount);
        vm.prank(alice);
        tokenA.approve(address(vault), tokenAmount);

        vm.prank(alice);
        vault.payDirect(pid, address(tokenA), tokenAmount);

        // Check balances
        assertEq(vault.totalBalances(address(tokenA)), tokenAmount);
        assertEq(vault.byPayment(pid, address(tokenA)), tokenAmount);
        assertEq(tokenA.balanceOf(address(vault)), tokenAmount);
        assertEq(tokenA.balanceOf(alice), 0);
    }

    function test_PayDirect_ZeroPaymentId_Reverts() public {
        vm.expectRevert(bytes("ZERO_PAYMENT_ID"));
        vault.payDirect{value: 1 ether}(bytes32(0), address(0), 1 ether);
    }

    function test_PayDirect_ETH_NoEthSent_Reverts() public {
        bytes32 pid = _uuid("direct-payment-no-eth");
        vm.expectRevert(bytes("NO_ETH_SENT"));
        vault.payDirect(pid, address(0), 1 ether);
    }

    function test_PayDirect_ETH_AmountMismatch_Reverts() public {
        bytes32 pid = _uuid("direct-payment-mismatch");
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        vm.expectRevert(bytes("ETH_AMOUNT_MISMATCH"));
        vault.payDirect{value: 1 ether}(pid, address(0), 0.5 ether);
    }

    function test_PayDirect_ERC20_WithETH_Reverts() public {
        bytes32 pid = _uuid("direct-payment-erc20-with-eth");
        tokenA.mint(alice, 100e18);
        vm.prank(alice);
        tokenA.approve(address(vault), 100e18);

        _fundEth(alice, 1 ether);
        vm.startPrank(alice);
        vm.expectRevert(bytes("NO_ETH_FOR_TOKEN_PAYMENT"));
        vault.payDirect{value: 1 ether}(pid, address(tokenA), 100e18);
        vm.stopPrank();
    }

    function test_PayDirect_ERC20_ZeroAmount_Reverts() public {
        bytes32 pid = _uuid("direct-payment-zero-amount");
        vm.expectRevert(bytes("ZERO_AMOUNT"));
        vault.payDirect(pid, address(tokenA), 0);
    }

    function test_PayDirect_ERC20_NotWhitelisted_Reverts() public {
        bytes32 pid = _uuid("direct-payment-not-whitelisted");
        tokenB.mint(alice, 100e18);
        vm.prank(alice);
        tokenB.approve(address(vault), 100e18);

        vm.prank(alice);
        vm.expectRevert(bytes("TOKEN_NOT_WHITELISTED"));
        vault.payDirect(pid, address(tokenB), 100e18);
    }

    function test_PayDirect_ERC20_InsufficientApproval_Reverts() public {
        bytes32 pid = _uuid("direct-payment-insufficient-approval");
        tokenA.mint(alice, 100e18);
        vm.prank(alice);
        tokenA.approve(address(vault), 50e18); // Approve less than trying to pay

        vm.prank(alice);
        vm.expectRevert(); // SafeERC20 will revert on insufficient allowance
        vault.payDirect(pid, address(tokenA), 100e18);
    }

    function test_PayDirect_Multiple_SamePaymentId() public {
        bytes32 pid = _uuid("direct-payment-multiple");

        // First ETH payment
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        vault.payDirect{value: 1 ether}(pid, address(0), 1 ether);

        // Second ETH payment from different user
        _fundEth(bob, 0.5 ether);
        vm.prank(bob);
        vault.payDirect{value: 0.5 ether}(pid, address(0), 0.5 ether);

        // TokenA payment
        tokenA.mint(alice, 200e18);
        vm.prank(alice);
        tokenA.approve(address(vault), 200e18);
        vm.prank(alice);
        vault.payDirect(pid, address(tokenA), 200e18);

        // Check cumulative balances for same payment ID
        assertEq(vault.byPayment(pid, address(0)), 1.5 ether);
        assertEq(vault.byPayment(pid, address(tokenA)), 200e18);
        assertEq(vault.totalBalances(address(0)), 1.5 ether);
        assertEq(vault.totalBalances(address(tokenA)), 200e18);
    }

    function test_PayDirect_WithdrawAfterDirectPayment() public {
        bytes32 pid = _uuid("direct-payment-then-withdraw");
        uint256 ethAmount = 2 ether;

        // Direct payment
        _fundEth(alice, ethAmount);
        vm.prank(alice);
        vault.payDirect{value: ethAmount}(pid, address(0), ethAmount);

        // Now withdraw with intent
        address beneficiary = bob;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;
        uint256 withdrawAmount = 0.8 ether;

        bytes memory sig = _signWithdraw(beneficiary, address(0), withdrawAmount, nonce, deadline);

        uint256 bobBalanceBefore = beneficiary.balance;
        vault.withdrawWithIntent(beneficiary, address(0), withdrawAmount, deadline, sig);

        // Check balances after withdrawal
        assertEq(beneficiary.balance, bobBalanceBefore + withdrawAmount);
        assertEq(vault.totalBalances(address(0)), ethAmount - withdrawAmount);
        assertEq(vault.byPayment(pid, address(0)), ethAmount); // Per-payment tracking unchanged
    }

    /* ───────────────────── Direct receives and events sanity ───────────────────── */

    function test_Vault_ReceiveDirectETH_CountsGlobally() public {
        _fundEth(alice, 0.33 ether);
        vm.prank(alice);
        (bool ok,) = payable(address(vault)).call{value: 0.33 ether}("");
        assertTrue(ok);
        assertEq(vault.totalBalances(address(0)), 0.33 ether);
        // per-payment for pid=0x0 is not asserted beyond Deposited event; we at least know totals grow
    }

    /* ───────────────────── Direct Withdrawal Tests (Intent Signer) ───────────────────── */

    function test_WithdrawDirect_ETH_Success() public {
        // Seed ETH via direct payment
        bytes32 pid = _uuid("direct-withdraw-eth");
        uint256 ethAmount = 2 ether;

        _fundEth(alice, ethAmount);
        vm.prank(alice);
        vault.payDirect{value: ethAmount}(pid, address(0), ethAmount);

        // Intent signer withdraws directly to beneficiary
        address beneficiary = bob;
        uint256 withdrawAmount = 0.8 ether;
        uint256 bobBalanceBefore = beneficiary.balance;

        vm.prank(signerAddr);
        vault.withdrawDirect(beneficiary, address(0), withdrawAmount);

        // Check balances
        assertEq(beneficiary.balance, bobBalanceBefore + withdrawAmount);
        assertEq(vault.totalBalances(address(0)), ethAmount - withdrawAmount);
        assertEq(payable(address(vault)).balance, ethAmount - withdrawAmount);
    }

    function test_WithdrawDirect_ERC20_Success() public {
        // Seed ERC20 via direct payment
        bytes32 pid = _uuid("direct-withdraw-erc20");
        uint256 tokenAmount = 1000e18;

        tokenA.mint(alice, tokenAmount);
        vm.prank(alice);
        tokenA.approve(address(vault), tokenAmount);
        vm.prank(alice);
        vault.payDirect(pid, address(tokenA), tokenAmount);

        // Intent signer withdraws directly to beneficiary
        address beneficiary = bob;
        uint256 withdrawAmount = 300e18;

        vm.prank(signerAddr);
        vault.withdrawDirect(beneficiary, address(tokenA), withdrawAmount);

        // Check balances
        assertEq(tokenA.balanceOf(beneficiary), withdrawAmount);
        assertEq(vault.totalBalances(address(tokenA)), tokenAmount - withdrawAmount);
        assertEq(tokenA.balanceOf(address(vault)), tokenAmount - withdrawAmount);
    }

    function test_WithdrawDirect_OnlyIntentSigner() public {
        // Seed some ETH
        bytes32 pid = _uuid("direct-withdraw-only-signer");
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        vault.payDirect{value: 1 ether}(pid, address(0), 1 ether);

        // Try to withdraw as non-signer (should fail)
        vm.prank(alice);
        vm.expectRevert(bytes("ONLY_INTENT_SIGNER"));
        vault.withdrawDirect(bob, address(0), 0.5 ether);

        // Try to withdraw as admin (should fail)
        vm.prank(admin);
        vm.expectRevert(bytes("ONLY_INTENT_SIGNER"));
        vault.withdrawDirect(bob, address(0), 0.5 ether);

        // Withdraw as intent signer (should succeed)
        vm.prank(signerAddr);
        vault.withdrawDirect(bob, address(0), 0.5 ether);
        assertEq(vault.totalBalances(address(0)), 0.5 ether);
    }

    function test_WithdrawDirect_ZeroBeneficiary_Reverts() public {
        // Seed some ETH
        bytes32 pid = _uuid("direct-withdraw-zero-benef");
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        vault.payDirect{value: 1 ether}(pid, address(0), 1 ether);

        vm.prank(signerAddr);
        vm.expectRevert(bytes("ZERO_BENEF"));
        vault.withdrawDirect(address(0), address(0), 0.5 ether);
    }

    function test_WithdrawDirect_ZeroAmount_Reverts() public {
        // Seed some ETH
        bytes32 pid = _uuid("direct-withdraw-zero-amount");
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        vault.payDirect{value: 1 ether}(pid, address(0), 1 ether);

        vm.prank(signerAddr);
        vm.expectRevert(bytes("ZERO_AMOUNT"));
        vault.withdrawDirect(bob, address(0), 0);
    }

    function test_WithdrawDirect_InsufficientTracked_Reverts() public {
        // No funds in vault
        vm.prank(signerAddr);
        vm.expectRevert(bytes("INSUFFICIENT_TRACKED"));
        vault.withdrawDirect(bob, address(0), 1 ether);
    }

    function test_WithdrawDirect_NativeSendFail_Reverts() public {
        // Seed some ETH
        bytes32 pid = _uuid("direct-withdraw-send-fail");
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        vault.payDirect{value: 1 ether}(pid, address(0), 1 ether);

        // Try to withdraw to reverting receiver
        vm.prank(signerAddr);
        vm.expectRevert(bytes("NATIVE_SEND_FAIL"));
        vault.withdrawDirect(address(badRecv), address(0), 0.5 ether);
    }

    function test_WithdrawDirect_Multiple_Withdrawals() public {
        // Seed funds
        bytes32 pid = _uuid("direct-withdraw-multiple");
        _fundEth(alice, 3 ether);
        vm.prank(alice);
        vault.payDirect{value: 3 ether}(pid, address(0), 3 ether);

        tokenA.mint(alice, 1500e18);
        vm.prank(alice);
        tokenA.approve(address(vault), 1500e18);
        vm.prank(alice);
        vault.payDirect(pid, address(tokenA), 1500e18);

        // Multiple withdrawals
        vm.startPrank(signerAddr);

        // First withdrawal - ETH to Alice
        vault.withdrawDirect(alice, address(0), 1 ether);
        assertEq(alice.balance, 1 ether);
        assertEq(vault.totalBalances(address(0)), 2 ether);

        // Second withdrawal - Tokens to Bob
        vault.withdrawDirect(bob, address(tokenA), 500e18);
        assertEq(tokenA.balanceOf(bob), 500e18);
        assertEq(vault.totalBalances(address(tokenA)), 1000e18);

        // Third withdrawal - ETH to Bob
        vault.withdrawDirect(bob, address(0), 0.5 ether);
        assertEq(bob.balance, 0.5 ether);
        assertEq(vault.totalBalances(address(0)), 1.5 ether);

        vm.stopPrank();
    }

    function test_WithdrawDirect_AfterIntentSignerChange() public {
        // Seed some ETH
        bytes32 pid = _uuid("direct-withdraw-signer-change");
        _fundEth(alice, 2 ether);
        vm.prank(alice);
        vault.payDirect{value: 2 ether}(pid, address(0), 2 ether);

        // Current signer can withdraw
        vm.prank(signerAddr);
        vault.withdrawDirect(bob, address(0), 0.5 ether);
        assertEq(vault.totalBalances(address(0)), 1.5 ether);

        // Change intent signer
        address newSigner = makeAddr("newSigner");
        vm.prank(admin);
        vault.setIntentSigner(newSigner);

        // Old signer can no longer withdraw
        vm.prank(signerAddr);
        vm.expectRevert(bytes("ONLY_INTENT_SIGNER"));
        vault.withdrawDirect(bob, address(0), 0.5 ether);

        // New signer can withdraw
        vm.prank(newSigner);
        vault.withdrawDirect(alice, address(0), 0.8 ether);
        assertEq(vault.totalBalances(address(0)), 0.7 ether);
    }

    function test_WithdrawDirect_Events() public {
        // Seed some funds
        bytes32 pid = _uuid("direct-withdraw-events");
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        vault.payDirect{value: 1 ether}(pid, address(0), 1 ether);

        // Check DirectWithdraw event is emitted
        vm.expectEmit(true, true, true, true);
        emit DirectWithdraw(signerAddr, bob, address(0), 0.6 ether);

        vm.prank(signerAddr);
        vault.withdrawDirect(bob, address(0), 0.6 ether);
    }

    // Helper to define the event for expectEmit
    event DirectWithdraw(address indexed signer, address indexed beneficiary, address indexed token, uint256 amount);

    /* ───────────────────── Factory functionality tests ───────────────────── */

    function test_PaymentIdFromUuid() public {
        string memory uuid = "123e4567-e89b-12d3-a456-426614174000";
        bytes32 expected = keccak256(bytes(uuid));
        bytes32 actual = vault.paymentIdFromUuid(uuid);
        assertEq(actual, expected);
    }

    function test_WalletAddressFromUuid() public {
        string memory uuid = "123e4567-e89b-12d3-a456-426614174000";
        bytes32 pid = vault.paymentIdFromUuid(uuid);
        address expected = vault.walletAddress(pid);
        address actual = vault.walletAddressFromUuid(uuid);
        assertEq(actual, expected);
    }

    /* ───────────────────── Fuzz-ish properties ───────────────────── */

    function testFuzz_Create2_PredictionStable(string memory invoice) public {
        bytes32 pid = keccak256(bytes(invoice));
        address a1 = vault.walletAddress(pid);
        address a2 = vault.walletAddress(pid);
        assertEq(a1, a2);
        if (a1.code.length == 0) {
            address w = vault.sweep(pid, address(0), address(0));
            assertEq(w, a1);
        }
    }

    function testFuzz_WithdrawWithIntent_ExactNonces(address user, uint96 amtWei) public {
        vm.assume(user != address(0));
        vm.assume(user.code.length == 0);
        vm.assume(uint160(user) > 20); // Avoid precompiled contracts and special addresses
        uint256 amt = uint256(amtWei) % 1e18 + 1; // at least 1 wei, at most < 1 ETH (keeps tests quick)

        // seed ETH
        bytes32 pid = _uuid("fuzz-withdraw-eth");
        address predicted = vault.walletAddress(pid);
        _fundEth(address(this), amt);
        (bool ok,) = predicted.call{value: amt}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), address(0));
        assertEq(vault.totalBalances(address(0)), amt);

        uint256 nonce = vault.nonces(user);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _signWithdraw(user, address(0), amt, nonce, deadline);

        vault.withdrawWithIntent(user, address(0), amt, deadline, sig);
        assertEq(vault.totalBalances(address(0)), 0);
        assertEq(vault.nonces(user), nonce + 1);

        // replay fails
        vm.expectRevert();
        vault.withdrawWithIntent(user, address(0), amt, deadline, sig);
    }
}
