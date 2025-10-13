// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";

contract PayInvoiceDirectScript is Script {
    function run() external {
        uint256 payerKey = vm.envUint("PRIVATE_KEY");
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");
        
        // Payment ID can be provided as bytes32 or UUID string
        bytes32 paymentId;
        try vm.envBytes32("PAYMENT_ID") returns (bytes32 id) {
            paymentId = id;
        } catch {
            string memory uuidString = vm.envString("PAYMENT_UUID");
            paymentId = DeterministicVault(payable(vaultAddress)).paymentIdFromUuid(uuidString);
        }
        
        // Token address (0x0 for ETH)
        address tokenAddress = vm.envAddress("TOKEN_ADDRESS");
        
        // Amount in wei for ETH, or token units for ERC20
        uint256 amount = vm.envUint("AMOUNT");
        
        console2.log("=== Pay Invoice Direct Script ===");
        console2.log("Vault Address:", vaultAddress);
        console2.log("Payment ID:", vm.toString(paymentId));
        console2.log("Token Address:", tokenAddress);
        console2.log("Amount:", amount);
        
        DeterministicVault vault = DeterministicVault(payable(vaultAddress));
        address walletAddress = vault.walletAddress(paymentId);
        console2.log("Target Wallet Address:", walletAddress);
        
        address payerAddress = vm.addr(payerKey);
        console2.log("Payer Address:", payerAddress);
        
        // Pre-payment validation and info
        console2.log("\n=== Pre-Payment Validation ===");
        
        if (tokenAddress == address(0)) {
            // ETH Payment
            console2.log("Payment Type: Native ETH");
            uint256 payerBalance = payerAddress.balance;
            console2.log("Payer ETH Balance:", payerBalance);
            
            require(payerBalance >= amount, "Insufficient ETH balance");
            console2.log("ETH Amount to Send:", amount);
        } else {
            // ERC20 Payment
            console2.log("Payment Type: ERC20 Token");
            console2.log("Token Symbol:", _getTokenSymbol(tokenAddress));
            console2.log("Token Name:", _getTokenName(tokenAddress));
            uint8 decimals = _getTokenDecimals(tokenAddress);
            console2.log("Token Decimals:", decimals);
            
            IERC20 token = IERC20(tokenAddress);
            uint256 payerBalance = token.balanceOf(payerAddress);
            console2.log("Payer Token Balance:", payerBalance);
            
            require(payerBalance >= amount, "Insufficient token balance");
            console2.log("Token Amount to Send:", amount);
        }
        
        // Check wallet current balance
        console2.log("\n=== Target Wallet Status ===");
        if (tokenAddress == address(0)) {
            console2.log("Wallet Current ETH Balance:", walletAddress.balance);
        } else {
            try IERC20(tokenAddress).balanceOf(walletAddress) returns (uint256 walletBalance) {
                console2.log("Wallet Current Token Balance:", walletBalance);
            } catch {
                console2.log("Wallet Current Token Balance: Unable to fetch");
            }
        }
        
        vm.startBroadcast(payerKey);
        
        console2.log("\n=== Executing Direct Payment ===");
        
        if (tokenAddress == address(0)) {
            // Send ETH directly to the deterministic wallet
            console2.log("Sending ETH to wallet...");
            (bool success, ) = payable(walletAddress).call{value: amount}("");
            require(success, "ETH transfer failed");
            console2.log("ETH transfer completed!");
        } else {
            // Send ERC20 tokens directly to the deterministic wallet
            console2.log("Sending tokens to wallet...");
            IERC20 token = IERC20(tokenAddress);
            bool success = token.transfer(walletAddress, amount);
            require(success, "Token transfer failed");
            console2.log("Token transfer completed!");
        }
        
        vm.stopBroadcast();
        
        // Post-payment verification
        console2.log("\n=== Post-Payment Verification ===");
        
        if (tokenAddress == address(0)) {
            uint256 newWalletBalance = walletAddress.balance;
            console2.log("Wallet New ETH Balance:", newWalletBalance);
            console2.log("Payment Successful:", newWalletBalance > 0 ? "YES" : "UNKNOWN");
        } else {
            try IERC20(tokenAddress).balanceOf(walletAddress) returns (uint256 newWalletBalance) {
                console2.log("Wallet New Token Balance:", newWalletBalance);
                console2.log("Payment Successful:", newWalletBalance > 0 ? "YES" : "UNKNOWN");
            } catch {
                console2.log("Unable to verify token balance");
            }
        }
        
        console2.log("\n=== Summary ===");
        console2.log("Payment Method: Direct Transfer");
        console2.log("Payment ID:", vm.toString(paymentId));
        console2.log("Target Wallet:", walletAddress);
        console2.log("Amount Sent:", amount);
        console2.log("Transaction completed successfully!");
    }
    
    function _getTokenSymbol(address token) internal view returns (string memory) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("symbol()"));
        return success && data.length > 0 ? abi.decode(data, (string)) : "UNKNOWN";
    }
    
    function _getTokenName(address token) internal view returns (string memory) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("name()"));
        return success && data.length > 0 ? abi.decode(data, (string)) : "Unknown Token";
    }
    
    function _getTokenDecimals(address token) internal view returns (uint8) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("decimals()"));
        return success && data.length == 32 ? abi.decode(data, (uint8)) : 18;
    }
}

/*
Usage Examples:

=== Pay with ETH (Native) ===
export VAULT_ADDRESS="0xdDFb667e2aC4B2F209b6D82e38133d1f36f6e0F4"
export PAYMENT_UUID="fa843d56-faae-42d4-aeba-34160a517668"
export TOKEN_ADDRESS="0x0000000000000000000000000000000000000000"
export AMOUNT="100000000000000000"  # 0.1 ETH in wei
export PRIVATE_KEY="your_private_key"

forge script script/PayInvoiceDirect.s.sol:PayInvoiceDirectScript \
  --rpc-url $RPC_URL --broadcast

=== Pay with ERC20 Token ===
export VAULT_ADDRESS="0xdDFb667e2aC4B2F209b6D82e38133d1f36f6e0F4"
export PAYMENT_UUID="fa843d56-faae-42d4-aeba-34160a517668"
export TOKEN_ADDRESS="0xa0b86a33e6444e6644ca95bf4c2b7a3d0ef2ced0"  # Token contract address
export AMOUNT="1000000000000000000000"  # 1000 tokens (adjust for decimals)
export PRIVATE_KEY="your_private_key"

forge script script/PayInvoiceDirect.s.sol:PayInvoiceDirectScript \
  --rpc-url $RPC_URL --broadcast

=== Alternative: Use Payment ID directly ===
export PAYMENT_ID="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
# ... other exports

=== Dry Run (No Broadcasting) ===
forge script script/PayInvoiceDirect.s.sol:PayInvoiceDirectScript \
  --rpc-url $RPC_URL

Note: 
- Use TOKEN_ADDRESS="0x0000000000000000000000000000000000000000" for ETH payments
- AMOUNT should be in wei for ETH, or token base units for ERC20
- Make sure you have sufficient balance and gas for the transaction
*/
