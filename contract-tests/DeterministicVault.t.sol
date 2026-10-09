// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {DeterministicVault} from "../contracts/DeterministicVault.sol";
import {DeterministicVaultProxy} from "../contracts/proxy/DeterministicVaultProxy.sol";
import {PaymentWallet} from "../contracts/PaymentWallet.sol";
import {IDeterministicVault} from "../contracts/interfaces/IDeterministicVault.sol";
import {IPaymentWallet} from "../contracts/interfaces/IPaymentWallet.sol";

import {MockERC20} from "./mocks/MockERC20.sol";
import {MockERC20Permit} from "./mocks/MockERC20Permit.sol";
import {MockERC20TransferWithAuthorization} from "./mocks/MockERC20TransferWithAuthorization.sol";
import {Receiver, RevertingReceiver} from "./mocks/TestReceivers.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20TransferWithAuthorization} from "../contracts/interfaces/IERC20TransferWithAuthorization.sol";

/**
 * @title DeterministicVaultTest
 * @dev Test suite for the DeterministicVault system (vault acts as its own factory)
 */
contract DeterministicVaultTest is Test {
    DeterministicVault vault;
    MockERC20 tokenA;
    MockERC20 tokenB;
    MockERC20Permit tokenPermit;
    MockERC20TransferWithAuthorization tokenTransferAuth;
    Receiver recv;
    RevertingReceiver badRecv;

    // test actors
    address admin = makeAddr("admin");
    address alice = makeAddr("alice");
    address bob   = makeAddr("bob");

    // signer keypair for EIP-712 intents
    uint256 signerPk;
    address signerAddr;
    
    // permit signer keypair (alice's actual address will be derived from this)
    uint256 alicePk;
    address aliceAddr;

    function setUp() public {
        // Deploy implementation (has _disableInitializers() for security)
        DeterministicVault vaultImpl = new DeterministicVault();
        
        // Deploy proxy with initialization (proxy pattern)
        bytes memory vaultData = abi.encodeWithSelector(
            DeterministicVault.initialize.selector
        );
        
        vm.prank(admin);
        DeterministicVaultProxy proxy = new DeterministicVaultProxy(
            address(vaultImpl),
            vaultData
        );
        vault = DeterministicVault(payable(address(proxy)));

        tokenA = new MockERC20("TokenA","TKA");
        tokenB = new MockERC20("TokenB","TKB");
        tokenPermit = new MockERC20Permit("TokenPermit", "TP");
        tokenTransferAuth = new MockERC20TransferWithAuthorization("TokenTransferAuth", "TTA");
        recv = new Receiver();
        badRecv = new RevertingReceiver();

        // configure signer
        signerPk = 0xA11CE; // arbitrary
        signerAddr = vm.addr(signerPk);
        
        // configure permit signer (alice)
        alicePk = 0x1A11CE; // arbitrary, different from signerPk
        aliceAddr = vm.addr(alicePk); // Get the address that corresponds to alicePk

        vm.prank(admin);
        vault.setIntentSigner(signerAddr);

        // whitelist TokenA, TokenPermit, and TokenTransferAuth
        vm.prank(admin);
        vault.setWhitelist(address(tokenA), true);
        vm.prank(admin);
        vault.setWhitelist(address(tokenPermit), true);
        vm.prank(admin);
        vault.setWhitelist(address(tokenTransferAuth), true);
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

    /**
     * @dev Helper to sign EIP-2612 permit signature
     * @param owner The token owner
     * @param spender The spender (vault)
     * @param value The amount to approve
     * @param nonce The owner's nonce
     * @param deadline The deadline
     * @param token The token contract
     * @param ownerPk The private key of the owner
     * @return v The recovery byte of the signature
     * @return r The r component of the signature
     * @return s The s component of the signature
     */
    function _signPermit(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline,
        IERC20Permit token,
        uint256 ownerPk
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline));
        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        return vm.sign(ownerPk, digest);
    }

    /**
     * @dev Helper to sign EIP-3009 transferWithAuthorization signature
     * @param from The token owner
     * @param to The recipient (vault)
     * @param value The amount to transfer
     * @param validAfter The timestamp after which the authorization is valid
     * @param validBefore The timestamp before which the authorization is valid
     * @param nonce A unique nonce
     * @param token The token contract
     * @param ownerPk The private key of the owner
     * @return v The recovery byte of the signature
     * @return r The r component of the signature
     * @return s The s component of the signature
     */
    function _signTransferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        IERC20TransferWithAuthorization token,
        uint256 ownerPk
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
            "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );
        bytes32 structHash = keccak256(
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
        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        return vm.sign(ownerPk, digest);
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

        // Accounting: ETH + TokenA booked

        // Totals reflect both
        assertEq(vault.totalBalances(address(0)), 1 ether);
        assertEq(vault.totalBalances(address(tokenA)), 1_000e18);

        // Vault holds the actual assets
        assertEq(payable(address(vault)).balance, 1 ether);
        assertEq(tokenA.balanceOf(payable(address(vault))), 1_000e18);
    }

    /* ───────────────────── Non-whitelisted token is transferred-in but NOT accounted ───────────────────── */

    function test_Sweep_NonWhitelistedToken_Reverts_OLD() public {
        bytes32 pid = _uuid("invoice-nonwl-1");
        address predicted = vault.walletAddress(pid);

        tokenB.mint(predicted, 777e18);
        assertEq(tokenB.balanceOf(predicted), 777e18);

        // Sweep specifying TokenB (NOT whitelisted) should revert
        vm.expectRevert(bytes("CALLBACK_FAILED"));  // Error happens in callback
        vault.sweep(pid, address(tokenB), alice);

        // Token should remain in wallet (not transferred)
        assertEq(tokenB.balanceOf(predicted), 777e18);
        assertEq(tokenB.balanceOf(payable(address(vault))), 0);
        assertEq(vault.totalBalances(address(tokenB)), 0);
    }

    /* ───────────────────── Batch Sweep Tests ───────────────────── */

    function test_SweepBatch_ETHOnly_MultiplePayments() public {
        bytes32 pid1 = _uuid("batch-eth-1");
        bytes32 pid2 = _uuid("batch-eth-2");
        bytes32 pid3 = _uuid("batch-eth-3");
        
        address predicted1 = vault.walletAddress(pid1);
        address predicted2 = vault.walletAddress(pid2);
        address predicted3 = vault.walletAddress(pid3);
        
        // Fund all wallets
        _fundEth(alice, 5 ether);
        vm.prank(alice);
        (bool ok1,) = predicted1.call{value: 1 ether}("");
        assertTrue(ok1);
        vm.prank(alice);
        (bool ok2,) = predicted2.call{value: 2 ether}("");
        assertTrue(ok2);
        vm.prank(alice);
        (bool ok3,) = predicted3.call{value: 1.5 ether}("");
        assertTrue(ok3);
        
        // Batch sweep
        bytes32[] memory paymentIds = new bytes32[](3);
        address[] memory tokens = new address[](3);
        address[] memory payers = new address[](3);
        
        paymentIds[0] = pid1;
        paymentIds[1] = pid2;
        paymentIds[2] = pid3;
        tokens[0] = address(0);
        tokens[1] = address(0);
        tokens[2] = address(0);
        payers[0] = alice;
        payers[1] = bob;
        payers[2] = alice;
        
        address[] memory wallets = vault.sweepBatch(paymentIds, tokens, payers);
        
        // Verify wallets
        assertEq(wallets[0], predicted1);
        assertEq(wallets[1], predicted2);
        assertEq(wallets[2], predicted3);
        assertEq(wallets.length, 3);
        
        // Verify all wallets are deployed
        assertGt(wallets[0].code.length, 0);
        assertGt(wallets[1].code.length, 0);
        assertGt(wallets[2].code.length, 0);
        
        // Verify balances
        assertEq(vault.totalBalances(address(0)), 4.5 ether);
        assertEq(payable(address(vault)).balance, 4.5 ether);
        
        // Verify wallets are swept
        assertTrue(PaymentWallet(payable(wallets[0])).swept());
        assertTrue(PaymentWallet(payable(wallets[1])).swept());
        assertTrue(PaymentWallet(payable(wallets[2])).swept());
    }

    function test_SweepBatch_MixedTokens() public {
        bytes32 pid1 = _uuid("batch-mixed-1");
        bytes32 pid2 = _uuid("batch-mixed-2");
        
        address predicted1 = vault.walletAddress(pid1);
        address predicted2 = vault.walletAddress(pid2);
        
        // Fund wallet 1 with ETH
        _fundEth(alice, 1 ether);
        vm.prank(alice);
        (bool ok1,) = predicted1.call{value: 1 ether}("");
        assertTrue(ok1);
        
        // Fund wallet 2 with TokenA
        tokenA.mint(predicted2, 500e18);
        
        // Batch sweep
        bytes32[] memory paymentIds = new bytes32[](2);
        address[] memory tokens = new address[](2);
        address[] memory payers = new address[](2);
        
        paymentIds[0] = pid1;
        paymentIds[1] = pid2;
        tokens[0] = address(0);
        tokens[1] = address(tokenA);
        payers[0] = alice;
        payers[1] = bob;
        
        address[] memory wallets = vault.sweepBatch(paymentIds, tokens, payers);
        
        // Verify balances
        assertEq(vault.totalBalances(address(0)), 1 ether);
        assertEq(vault.totalBalances(address(tokenA)), 500e18);
        assertEq(payable(address(vault)).balance, 1 ether);
        assertEq(tokenA.balanceOf(address(vault)), 500e18);
    }

    function test_SweepBatch_EmptyArray_Reverts() public {
        bytes32[] memory paymentIds = new bytes32[](0);
        address[] memory tokens = new address[](0);
        address[] memory payers = new address[](0);
        
        vm.expectRevert(bytes("EMPTY_ARRAY"));
        vault.sweepBatch(paymentIds, tokens, payers);
    }

    function test_SweepBatch_ArrayLengthMismatch_Tokens_Reverts() public {
        bytes32 pid1 = _uuid("batch-mismatch-1");
        bytes32[] memory paymentIds = new bytes32[](1);
        address[] memory tokens = new address[](2); // Wrong length
        address[] memory payers = new address[](1);
        
        paymentIds[0] = pid1;
        payers[0] = alice;
        
        vm.expectRevert(bytes("ARRAY_LENGTH_MISMATCH"));
        vault.sweepBatch(paymentIds, tokens, payers);
    }

    function test_SweepBatch_ArrayLengthMismatch_Payers_Reverts() public {
        bytes32 pid1 = _uuid("batch-mismatch-2");
        bytes32[] memory paymentIds = new bytes32[](1);
        address[] memory tokens = new address[](1);
        address[] memory payers = new address[](2); // Wrong length
        
        paymentIds[0] = pid1;
        tokens[0] = address(0);
        
        vm.expectRevert(bytes("ARRAY_LENGTH_MISMATCH"));
        vault.sweepBatch(paymentIds, tokens, payers);
    }

    function test_SweepBatch_LargeBatch() public {
        uint256 batchSize = 10;
        bytes32[] memory paymentIds = new bytes32[](batchSize);
        address[] memory tokens = new address[](batchSize);
        address[] memory payers = new address[](batchSize);
        
        _fundEth(alice, batchSize * 1 ether);
        
        // Prepare all payments
        for (uint256 i = 0; i < batchSize; i++) {
            bytes32 pid = _uuid(string(abi.encodePacked("batch-large-", i)));
            paymentIds[i] = pid;
            tokens[i] = address(0);
            payers[i] = alice;
            
            address predicted = vault.walletAddress(pid);
            vm.prank(alice);
            (bool ok,) = predicted.call{value: 1 ether}("");
            assertTrue(ok);
        }
        
        // Execute batch sweep
        address[] memory wallets = vault.sweepBatch(paymentIds, tokens, payers);
        
        // Verify all wallets deployed
        assertEq(wallets.length, batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            assertGt(wallets[i].code.length, 0);
            assertTrue(PaymentWallet(payable(wallets[i])).swept());
        }
        
        // Verify total balance
        assertEq(vault.totalBalances(address(0)), batchSize * 1 ether);
    }

    function test_SweepBatch_SomeAlreadyDeployed() public {
        bytes32 pid1 = _uuid("batch-deployed-1");
        bytes32 pid2 = _uuid("batch-deployed-2");
        
        address predicted1 = vault.walletAddress(pid1);
        address predicted2 = vault.walletAddress(pid2);
        
        // Deploy first wallet manually
        _fundEth(alice, 3 ether);
        vm.prank(alice);
        (bool ok1,) = predicted1.call{value: 1 ether}("");
        assertTrue(ok1);
        address wallet1 = vault.sweep(pid1, address(0), alice);
        assertEq(wallet1, predicted1);
        
        // Fund second wallet
        vm.prank(alice);
        (bool ok2,) = predicted2.call{value: 1 ether}("");
        assertTrue(ok2);
        
        // Batch sweep (first already deployed, second not)
        bytes32[] memory paymentIds = new bytes32[](2);
        address[] memory tokens = new address[](2);
        address[] memory payers = new address[](2);
        
        paymentIds[0] = pid1;
        paymentIds[1] = pid2;
        tokens[0] = address(0);
        tokens[1] = address(0);
        payers[0] = alice;
        payers[1] = bob;
        
        // Should revert because first wallet already swept
        vm.expectRevert(bytes("ALREADY_SWEPT"));
        vault.sweepBatch(paymentIds, tokens, payers);
    }

    function test_SweepBatch_NonWhitelistedToken_Reverts() public {
        bytes32 pid1 = _uuid("batch-nonwl-1");
        address predicted1 = vault.walletAddress(pid1);
        
        tokenB.mint(predicted1, 100e18);
        
        bytes32[] memory paymentIds = new bytes32[](1);
        address[] memory tokens = new address[](1);
        address[] memory payers = new address[](1);
        
        paymentIds[0] = pid1;
        tokens[0] = address(tokenB); // Not whitelisted
        payers[0] = alice;
        
        vm.expectRevert(bytes("CALLBACK_FAILED"));
        vault.sweepBatch(paymentIds, tokens, payers);
    }

    /* ───────────────────── Only-one-time sweep enforced ───────────────────── */

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

        // Re-sweep: vault asks wallet to sweep, but wallet already swept -> revert
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

    // adminCall function removed to reduce Blockaid warnings and eliminate powerful admin escape hatch

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

    function test_Wallet_SweepToVault_OnlyVault() public {
        bytes32 pid = _uuid("invoice-walletguard");
        address wallet = vault.sweep(pid, address(0), alice);
        // second sweep will revert on ALREADY_SWEPT; but try to call sweep directly first (only vault)
        vm.expectRevert(bytes("ONLY_VAULT_FACTORY"));
        IPaymentWallet(wallet).sweepToVault(pid, alice, payable(address(vault)), address(0));
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
        vm.expectRevert(bytes("INSUFFICIENT_ALLOWANCE"));
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

        // Check cumulative balances
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
    }

    /* ───────────────────── Direct Payment with Transfer Authorization Tests (EIP-3009) ───────────────────── */

    function test_PayDirectWithTransferAuthorization_Success() public {
        bytes32 pid = _uuid("direct-payment-transfer-auth");
        uint256 tokenAmount = 500e18;

        // Mint tokens to aliceAddr (the address that corresponds to alicePk)
        tokenTransferAuth.mint(aliceAddr, tokenAmount);
        assertEq(tokenTransferAuth.balanceOf(aliceAddr), tokenAmount);

        // Prepare authorization parameters
        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("unique-nonce-1");

        // Sign the transferWithAuthorization
        (uint8 v, bytes32 r, bytes32 s) = _signTransferWithAuthorization(
            aliceAddr,
            address(vault),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            IERC20TransferWithAuthorization(address(tokenTransferAuth)),
            alicePk
        );

        // Execute payment with transfer authorization
        vm.prank(aliceAddr);
        vault.payDirectWithTransferAuthorization(
            pid,
            address(tokenTransferAuth),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );

        // Check balances
        assertEq(vault.totalBalances(address(tokenTransferAuth)), tokenAmount);
        assertEq(tokenTransferAuth.balanceOf(address(vault)), tokenAmount);
        assertEq(tokenTransferAuth.balanceOf(aliceAddr), 0);
    }

    function test_PayDirectWithTransferAuthorization_ZeroPaymentId_Reverts() public {
        uint256 tokenAmount = 100e18;
        tokenTransferAuth.mint(aliceAddr, tokenAmount);
        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-1");

        (uint8 v, bytes32 r, bytes32 s) = _signTransferWithAuthorization(
            aliceAddr,
            address(vault),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            IERC20TransferWithAuthorization(address(tokenTransferAuth)),
            alicePk
        );

        vm.prank(aliceAddr);
        vm.expectRevert(bytes("ZERO_PAYMENT_ID"));
        vault.payDirectWithTransferAuthorization(
            bytes32(0),
            address(tokenTransferAuth),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
    }

    function test_PayDirectWithTransferAuthorization_Token0Forbidden_Reverts() public {
        bytes32 pid = _uuid("direct-payment-transfer-auth-token0");
        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-2");

        vm.prank(aliceAddr);
        vm.expectRevert(bytes("TOKEN_0_FORBIDDEN"));
        vault.payDirectWithTransferAuthorization(
            pid,
            address(0),
            1 ether,
            validAfter,
            validBefore,
            nonce,
            0,
            bytes32(0),
            bytes32(0)
        );
    }

    function test_PayDirectWithTransferAuthorization_ZeroAmount_Reverts() public {
        bytes32 pid = _uuid("direct-payment-transfer-auth-zero");
        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-3");

        vm.prank(aliceAddr);
        vm.expectRevert(bytes("ZERO_AMOUNT"));
        vault.payDirectWithTransferAuthorization(
            pid,
            address(tokenTransferAuth),
            0,
            validAfter,
            validBefore,
            nonce,
            0,
            bytes32(0),
            bytes32(0)
        );
    }

    function test_PayDirectWithTransferAuthorization_NotWhitelisted_Reverts() public {
        bytes32 pid = _uuid("direct-payment-transfer-auth-not-whitelisted");
        uint256 tokenAmount = 100e18;
        tokenTransferAuth.mint(aliceAddr, tokenAmount);
        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-4");

        // Remove token from whitelist
        vm.prank(admin);
        vault.setWhitelist(address(tokenTransferAuth), false);

        (uint8 v, bytes32 r, bytes32 s) = _signTransferWithAuthorization(
            aliceAddr,
            address(vault),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            IERC20TransferWithAuthorization(address(tokenTransferAuth)),
            alicePk
        );

        vm.prank(aliceAddr);
        vm.expectRevert(bytes("TOKEN_NOT_WHITELISTED"));
        vault.payDirectWithTransferAuthorization(
            pid,
            address(tokenTransferAuth),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
    }

    function test_PayDirectWithTransferAuthorization_NotYetValid_Reverts() public {
        bytes32 pid = _uuid("direct-payment-transfer-auth-not-yet-valid");
        uint256 tokenAmount = 100e18;
        tokenTransferAuth.mint(aliceAddr, tokenAmount);
        uint256 validAfter = block.timestamp + 1 days; // Future timestamp
        uint256 validBefore = block.timestamp + 2 days;
        bytes32 nonce = keccak256("nonce-5");

        (uint8 v, bytes32 r, bytes32 s) = _signTransferWithAuthorization(
            aliceAddr,
            address(vault),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            IERC20TransferWithAuthorization(address(tokenTransferAuth)),
            alicePk
        );

        vm.prank(aliceAddr);
        vm.expectRevert(bytes("AUTHORIZATION_NOT_YET_VALID"));
        vault.payDirectWithTransferAuthorization(
            pid,
            address(tokenTransferAuth),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
    }

    function test_PayDirectWithTransferAuthorization_Expired_Reverts() public {
        bytes32 pid = _uuid("direct-payment-transfer-auth-expired");
        uint256 tokenAmount = 100e18;
        tokenTransferAuth.mint(aliceAddr, tokenAmount);
        uint256 validAfter = 0; // Start from epoch
        uint256 validBefore = block.timestamp - 1; // Already expired
        bytes32 nonce = keccak256("nonce-6");

        (uint8 v, bytes32 r, bytes32 s) = _signTransferWithAuthorization(
            aliceAddr,
            address(vault),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            IERC20TransferWithAuthorization(address(tokenTransferAuth)),
            alicePk
        );

        vm.prank(aliceAddr);
        vm.expectRevert(bytes("AUTHORIZATION_EXPIRED"));
        vault.payDirectWithTransferAuthorization(
            pid,
            address(tokenTransferAuth),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
    }

    function test_PayDirectWithTransferAuthorization_InvalidSignature_Reverts() public {
        bytes32 pid = _uuid("direct-payment-transfer-auth-invalid-sig");
        uint256 tokenAmount = 100e18;
        tokenTransferAuth.mint(aliceAddr, tokenAmount);
        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-7");

        // Use wrong signature (from bob instead of aliceAddr)
        (uint8 v, bytes32 r, bytes32 s) = _signTransferWithAuthorization(
            bob, // Wrong signer
            address(vault),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            IERC20TransferWithAuthorization(address(tokenTransferAuth)),
            alicePk
        );

        vm.prank(aliceAddr);
        vm.expectRevert(bytes("TRANSFER_WITH_AUTHORIZATION_FAILED"));
        vault.payDirectWithTransferAuthorization(
            pid,
            address(tokenTransferAuth),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );
    }

    function test_PayDirectWithTransferAuthorization_ReplayAttack_Reverts() public {
        bytes32 pid = _uuid("direct-payment-transfer-auth-replay");
        uint256 tokenAmount = 100e18;
        tokenTransferAuth.mint(aliceAddr, tokenAmount);
        uint256 validAfter = block.timestamp;
        uint256 validBefore = block.timestamp + 1 days;
        bytes32 nonce = keccak256("nonce-8");

        (uint8 v, bytes32 r, bytes32 s) = _signTransferWithAuthorization(
            aliceAddr,
            address(vault),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            IERC20TransferWithAuthorization(address(tokenTransferAuth)),
            alicePk
        );

        // First use - should succeed
        vm.prank(aliceAddr);
        vault.payDirectWithTransferAuthorization(
            pid,
            address(tokenTransferAuth),
            tokenAmount,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );

        // Mint more tokens for second attempt
        tokenTransferAuth.mint(aliceAddr, tokenAmount);

        // Replay attack - should fail
        vm.prank(aliceAddr);
        vm.expectRevert(bytes("TRANSFER_WITH_AUTHORIZATION_FAILED"));
        vault.payDirectWithTransferAuthorization(
            pid,
            address(tokenTransferAuth),
            tokenAmount,
            validAfter,
            validBefore,
            nonce, // Same nonce
            v,
            r,
            s
        );
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

    // Helper to define the event for expectEmit
    event DirectPayment(bytes32 indexed paymentId, address indexed payer, address indexed token, uint256 amount);
    event Deposited(bytes32 indexed paymentId, address indexed payer, address indexed token, uint256 amount);

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

    /* ───────────────────── Daily Limit Tests ───────────────────── */

    function test_SetDailyLimit_OnlyOwner() public {
        vm.prank(admin);
        vault.setDailyLimit(address(tokenA), 1000e18);
        assertEq(vault.dailyLimits(address(tokenA)), 1000e18);

        // Non-owner should fail
        vm.prank(alice);
        vm.expectRevert();
        vault.setDailyLimit(address(tokenA), 500e18);
    }

    function test_SetDailyLimit_OnlyWhitelistedTokens() public {
        // Set limit for whitelisted token should succeed
        vm.prank(admin);
        vault.setDailyLimit(address(tokenA), 1000e18);
        assertEq(vault.dailyLimits(address(tokenA)), 1000e18);

        // Set limit for non-whitelisted token should fail
        vm.prank(admin);
        vm.expectRevert(bytes("TOKEN_NOT_WHITELISTED"));
        vault.setDailyLimit(address(tokenB), 1000e18);
    }

    function test_SetDailyLimit_ETH_AlwaysAllowed() public {
        // ETH (address(0)) should always be allowed even if not whitelisted
        vm.prank(admin);
        vault.setDailyLimit(address(0), 10 ether);
        assertEq(vault.dailyLimits(address(0)), 10 ether);
    }

    function test_DailyLimit_Default_NoLimit() public {
        // By default, daily limit should be 0 (which means no limit enforced if MAX_VALUE)
        // Actually, default is 0, which means disabled. Let's check that withdrawals work without limit set
        bytes32 pid = _uuid("daily-limit-default");
        _fundEth(alice, 5 ether);
        vm.prank(alice);
        (bool ok,) = vault.walletAddress(pid).call{value: 5 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        // Withdrawal should work without limit set (default behavior)
        address beneficiary = bob;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _signWithdraw(beneficiary, address(0), 5 ether, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(0), 5 ether, deadline, sig);
        assertEq(beneficiary.balance, 5 ether);
    }

    function test_DailyLimit_Zero_DisablesWithdrawals() public {
        // Set daily limit to 0
        vm.prank(admin);
        vault.setDailyLimit(address(0), 0);

        // Seed funds
        bytes32 pid = _uuid("daily-limit-zero");
        _fundEth(alice, 2 ether);
        vm.prank(alice);
        (bool ok,) = vault.walletAddress(pid).call{value: 2 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        // Withdrawal should fail
        address beneficiary = bob;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _signWithdraw(beneficiary, address(0), 1 ether, nonce, deadline);
        
        vm.expectRevert(bytes("DAILY_LIMIT_DISABLED"));
        vault.withdrawWithIntent(beneficiary, address(0), 1 ether, deadline, sig);
    }

    function test_DailyLimit_WithdrawWithIntent_Enforced() public {
        // Set daily limit to 2 ETH
        vm.prank(admin);
        vault.setDailyLimit(address(0), 2 ether);

        // Seed funds
        bytes32 pid = _uuid("daily-limit-intent");
        _fundEth(alice, 5 ether);
        vm.prank(alice);
        (bool ok,) = vault.walletAddress(pid).call{value: 5 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        address beneficiary = bob;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;

        // First withdrawal: 1.5 ETH (within limit)
        bytes memory sig1 = _signWithdraw(beneficiary, address(0), 1.5 ether, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(0), 1.5 ether, deadline, sig1);
        assertEq(beneficiary.balance, 1.5 ether);
        assertEq(vault.dailyWithdrawals(address(0), block.timestamp / 1 days), 1.5 ether);

        // Second withdrawal: 0.5 ETH (total 2 ETH, exactly at limit)
        nonce = vault.nonces(beneficiary);
        bytes memory sig2 = _signWithdraw(beneficiary, address(0), 0.5 ether, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(0), 0.5 ether, deadline, sig2);
        assertEq(beneficiary.balance, 2 ether);
        assertEq(vault.dailyWithdrawals(address(0), block.timestamp / 1 days), 2 ether);

        // Third withdrawal: 0.1 ETH (would exceed limit)
        nonce = vault.nonces(beneficiary);
        bytes memory sig3 = _signWithdraw(beneficiary, address(0), 0.1 ether, nonce, deadline);
        vm.expectRevert(bytes("DAILY_LIMIT_EXCEEDED"));
        vault.withdrawWithIntent(beneficiary, address(0), 0.1 ether, deadline, sig3);
    }


    function test_DailyLimit_ERC20_Enforced() public {
        // Set daily limit for tokenA
        vm.prank(admin);
        vault.setDailyLimit(address(tokenA), 500e18);

        // Seed funds
        bytes32 pid = _uuid("daily-limit-erc20");
        tokenA.mint(vault.walletAddress(pid), 1000e18);
        vault.sweep(pid, address(tokenA), alice);

        address beneficiary = bob;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;

        // First withdrawal: 300e18 (within limit)
        bytes memory sig1 = _signWithdraw(beneficiary, address(tokenA), 300e18, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(tokenA), 300e18, deadline, sig1);
        assertEq(tokenA.balanceOf(beneficiary), 300e18);
        assertEq(vault.dailyWithdrawals(address(tokenA), block.timestamp / 1 days), 300e18);

        // Second withdrawal: 200e18 (total 500e18, exactly at limit)
        nonce = vault.nonces(beneficiary);
        bytes memory sig2 = _signWithdraw(beneficiary, address(tokenA), 200e18, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(tokenA), 200e18, deadline, sig2);
        assertEq(tokenA.balanceOf(beneficiary), 500e18);
        assertEq(vault.dailyWithdrawals(address(tokenA), block.timestamp / 1 days), 500e18);

        // Third withdrawal: 1e18 (would exceed limit)
        nonce = vault.nonces(beneficiary);
        bytes memory sig3 = _signWithdraw(beneficiary, address(tokenA), 1e18, nonce, deadline);
        vm.expectRevert(bytes("DAILY_LIMIT_EXCEEDED"));
        vault.withdrawWithIntent(beneficiary, address(tokenA), 1e18, deadline, sig3);
    }

    function test_DailyLimit_ResetsOnNewDay() public {
        // Set daily limit to 1 ETH
        vm.prank(admin);
        vault.setDailyLimit(address(0), 1 ether);

        // Seed funds
        bytes32 pid = _uuid("daily-limit-reset");
        _fundEth(alice, 3 ether);
        vm.prank(alice);
        (bool ok,) = vault.walletAddress(pid).call{value: 3 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        address beneficiary = bob;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;

        // Withdraw full limit on day 1
        bytes memory sig1 = _signWithdraw(beneficiary, address(0), 1 ether, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(0), 1 ether, deadline, sig1);
        assertEq(beneficiary.balance, 1 ether);

        uint256 day1 = block.timestamp / 1 days;
        assertEq(vault.dailyWithdrawals(address(0), day1), 1 ether);

        // Advance time by 1 day
        vm.warp(block.timestamp + 1 days);

        // Should be able to withdraw again on new day
        nonce = vault.nonces(beneficiary);
        deadline = block.timestamp + 1 days;
        bytes memory sig2 = _signWithdraw(beneficiary, address(0), 1 ether, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(0), 1 ether, deadline, sig2);
        assertEq(beneficiary.balance, 2 ether);

        uint256 day2 = block.timestamp / 1 days;
        assertEq(vault.dailyWithdrawals(address(0), day2), 1 ether);
        assertEq(vault.dailyWithdrawals(address(0), day1), 1 ether); // Day 1 unchanged
    }

    function test_DailyLimit_MAX_VALUE_NoLimit() public {
        // Set daily limit to MAX_VALUE (no limit)
        vm.prank(admin);
        vault.setDailyLimit(address(0), type(uint256).max);

        // Seed funds
        bytes32 pid = _uuid("daily-limit-max");
        _fundEth(alice, 10 ether);
        vm.prank(alice);
        (bool ok,) = vault.walletAddress(pid).call{value: 10 ether}("");
        assertTrue(ok);
        vault.sweep(pid, address(0), alice);

        address beneficiary = bob;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;

        // Should be able to withdraw all funds in one go
        bytes memory sig = _signWithdraw(beneficiary, address(0), 10 ether, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(0), 10 ether, deadline, sig);
        assertEq(beneficiary.balance, 10 ether);

        // Daily withdrawals should still be 0 (not tracked when limit is MAX_VALUE)
        assertEq(vault.dailyWithdrawals(address(0), block.timestamp / 1 days), 0);
    }

    function test_DailyLimit_EventEmitted() public {
        vm.expectEmit(true, true, true, true);
        emit DailyLimitSet(address(tokenA), 1000e18);

        vm.prank(admin);
        vault.setDailyLimit(address(tokenA), 1000e18);
    }

    function test_DailyLimit_MultipleTokens_Independent() public {
        // Set different limits for different tokens
        vm.prank(admin);
        vault.setDailyLimit(address(0), 2 ether);
        vm.prank(admin);
        vault.setDailyLimit(address(tokenA), 1000e18);

        // Seed ETH
        bytes32 pid1 = _uuid("daily-limit-multi-eth");
        _fundEth(alice, 3 ether);
        vm.prank(alice);
        (bool ok,) = vault.walletAddress(pid1).call{value: 3 ether}("");
        assertTrue(ok);
        vault.sweep(pid1, address(0), alice);

        // Seed tokenA
        bytes32 pid2 = _uuid("daily-limit-multi-token");
        tokenA.mint(vault.walletAddress(pid2), 2000e18);
        vault.sweep(pid2, address(tokenA), alice);

        // Withdraw ETH up to limit
        address beneficiary = bob;
        uint256 nonce = vault.nonces(beneficiary);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sigEth = _signWithdraw(beneficiary, address(0), 2 ether, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(0), 2 ether, deadline, sigEth);
        assertEq(beneficiary.balance, 2 ether);

        // Withdraw tokenA up to limit (should work independently)
        nonce = vault.nonces(beneficiary);
        bytes memory sigToken = _signWithdraw(beneficiary, address(tokenA), 1000e18, nonce, deadline);
        vault.withdrawWithIntent(beneficiary, address(tokenA), 1000e18, deadline, sigToken);
        assertEq(tokenA.balanceOf(beneficiary), 1000e18);

        // Verify limits are tracked independently
        uint256 currentDay = block.timestamp / 1 days;
        assertEq(vault.dailyWithdrawals(address(0), currentDay), 2 ether);
        assertEq(vault.dailyWithdrawals(address(tokenA), currentDay), 1000e18);
    }

    // Helper to define the event for expectEmit
    event DailyLimitSet(address indexed token, uint256 limit);
}
