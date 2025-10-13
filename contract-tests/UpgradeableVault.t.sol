// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {PaymentWallet} from "../contracts/PaymentWallet.sol";
import {DeterministicVaultProxy} from "../contracts/proxy/DeterministicVaultProxy.sol";
import {PaymentWalletProxy} from "../contracts/proxy/PaymentWalletProxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract UpgradeableVaultTest is Test {
    DeterministicVault public vaultImpl;
    DeterministicVault public vaultProxy;
    PaymentWallet public walletImpl;
    MockERC20 public token;

    address public owner = address(1);
    address public user = address(2);
    uint256 public signerPk = 0xA11CE;
    address public intentSigner;

    function setUp() public {
        // Deploy implementation contracts
        vaultImpl = new DeterministicVault();
        walletImpl = new PaymentWallet();

        // Deploy proxy with implementation
        bytes memory vaultData = abi.encodeWithSelector(
            DeterministicVault.initialize.selector
        );

        vm.prank(owner);
        DeterministicVaultProxy proxy = new DeterministicVaultProxy(
            address(vaultImpl),
            vaultData
        );
        vaultProxy = DeterministicVault(payable(address(proxy)));

        // Deploy mock token
        token = new MockERC20("Test Token", "TEST");

        // Setup initial state
        intentSigner = vm.addr(signerPk);
        vm.startPrank(owner);
        vaultProxy.setIntentSigner(intentSigner);
        vaultProxy.setWhitelist(address(token), true);
        vm.stopPrank();

        // Fund user with tokens
        token.mint(user, 1000 ether);
    }

    function test_InitialState() public {
        assertEq(vaultProxy.intentSigner(), intentSigner);
        assertTrue(vaultProxy.tokenWhitelist(address(token)));
    }

    function test_DirectPayment() public {
        bytes32 paymentId = keccak256("test");
        uint256 amount = 100 ether;

        vm.startPrank(user);
        token.approve(address(vaultProxy), amount);
        vaultProxy.payDirect(paymentId, address(token), amount);
        vm.stopPrank();

        assertEq(vaultProxy.totalBalances(address(token)), amount);
        assertEq(vaultProxy.byPayment(paymentId, address(token)), amount);
    }

    function test_Sweep() public {
        bytes32 paymentId = keccak256("test");
        uint256 amount = 100 ether;

        // Send tokens to the deterministic wallet
        vm.startPrank(user);
        address walletAddr = vaultProxy.walletAddress(paymentId);
        token.transfer(walletAddr, amount);
        vm.stopPrank();

        // Sweep
        vaultProxy.sweep(paymentId, address(token), user);

        assertEq(vaultProxy.totalBalances(address(token)), amount);
        assertEq(vaultProxy.byPayment(paymentId, address(token)), amount);
    }

    function test_WithdrawWithIntent() public {
        bytes32 paymentId = keccak256("test");
        uint256 amount = 100 ether;

        // First make a payment
        vm.startPrank(user);
        token.approve(address(vaultProxy), amount);
        vaultProxy.payDirect(paymentId, address(token), amount);
        vm.stopPrank();

        // Create withdrawal signature
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = vaultProxy.nonces(user);
        bytes32 domainSeparator = vaultProxy.domainSeparator();
        
        bytes32 typeHash = keccak256(
            "WithdrawIntent(address beneficiary,address token,uint256 amount,uint256 nonce,uint256 deadline)"
        );
        bytes32 structHash = keccak256(abi.encode(typeHash, user, address(token), amount, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Withdraw
        vaultProxy.withdrawWithIntent(user, address(token), amount, deadline, signature);

        assertEq(vaultProxy.totalBalances(address(token)), 0);
        assertEq(token.balanceOf(user), 1000 ether);
    }

    function test_DirectWithdraw() public {
        bytes32 paymentId = keccak256("test");
        uint256 amount = 100 ether;

        // First make a payment
        vm.startPrank(user);
        token.approve(address(vaultProxy), amount);
        vaultProxy.payDirect(paymentId, address(token), amount);
        vm.stopPrank();

        // Direct withdraw by intent signer
        vm.prank(intentSigner);
        vaultProxy.withdrawDirect(user, address(token), amount);

        assertEq(vaultProxy.totalBalances(address(token)), 0);
        assertEq(token.balanceOf(user), 1000 ether);
    }

    function test_AdminTransfer() public {
        bytes32 paymentId = keccak256("test");
        uint256 amount = 100 ether;

        // First make a payment
        vm.startPrank(user);
        token.approve(address(vaultProxy), amount);
        vaultProxy.payDirect(paymentId, address(token), amount);
        vm.stopPrank();

        // Admin transfer
        vm.prank(owner);
        vaultProxy.adminTransfer(address(token), owner, amount);

        assertEq(vaultProxy.totalBalances(address(token)), 0);
        assertEq(token.balanceOf(owner), amount);
    }

    function test_RevertOnUnauthorizedUpgrade() public {
        DeterministicVault newImpl = new DeterministicVault();
        
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        vm.prank(user);
        ITransparentUpgradeableProxy(address(vaultProxy)).upgradeToAndCall(address(newImpl), "");
    }

    function test_SuccessfulUpgrade() public {
        DeterministicVault newImpl = new DeterministicVault();
        
        vm.prank(owner);
        ITransparentUpgradeableProxy(address(vaultProxy)).upgradeToAndCall(address(newImpl), "");

        // Verify state is preserved
        assertEq(vaultProxy.intentSigner(), intentSigner);
        assertTrue(vaultProxy.tokenWhitelist(address(token)));
    }
}
