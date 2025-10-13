// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";

contract PayInvoiceVaultScript is Script {
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
        
        console2.log("=== Pay Invoice Vault Script ===");
        console2.log("Vault Address:", vaultAddress);
        console2.log("Payment ID:", vm.toString(paymentId));
        console2.log("Token Address:", tokenAddress);
        console2.log("Amount:", amount);
        
        DeterministicVault vault = DeterministicVault(payable(vaultAddress));
        address walletAddress = vault.walletAddress(paymentId);
        console2.log("Associated Wallet Address:", walletAddress);
        
        address payerAddress = vm.addr(payerKey);
        console2.log("Payer Address:", payerAddress);
        
        // Pre-payment validation and info
        console2.log("\n=== Pre-Payment Validation ===");
        
        if (tokenAddress == address(0)) {
            // ETH Payment
            console2.log("Payment Type: Native ETH via Vault");
            uint256 payerBalance = payerAddress.balance;
            console2.log("Payer ETH Balance:", payerBalance);
            
            require(payerBalance >= amount, "Insufficient ETH balance");
            console2.log("ETH Amount to Send:", amount);
        } else {
            // ERC20 Payment
            console2.log("Payment Type: ERC20 Token via Vault");
            console2.log("Token Symbol:", _getTokenSymbol(tokenAddress));
            console2.log("Token Name:", _getTokenName(tokenAddress));
            uint8 decimals = _getTokenDecimals(tokenAddress);
            console2.log("Token Decimals:", decimals);
            
            IERC20 token = IERC20(tokenAddress);
            uint256 payerBalance = token.balanceOf(payerAddress);
            console2.log("Payer Token Balance:", payerBalance);
            
            require(payerBalance >= amount, "Insufficient token balance");
            
            // Check token allowance for vault
            uint256 allowance = token.allowance(payerAddress, vaultAddress);
            console2.log("Current Token Allowance:", allowance);
            
            if (allowance < amount) {
                console2.log("WARNING: Insufficient allowance. Required:", amount);
                console2.log("You may need to approve tokens first or increase allowance.");
            }
            
            console2.log("Token Amount to Send:", amount);
        }
        
        // Check vault balances before payment
        console2.log("\n=== Vault Status Before Payment ===");
        if (tokenAddress == address(0)) {
            console2.log("Vault ETH Balance:", vaultAddress.balance);
            try vault.totalBalances(address(0)) returns (uint256 trackedEth) {
                console2.log("Vault Tracked ETH:", trackedEth);
            } catch {
                console2.log("Vault Tracked ETH: Unable to fetch");
            }
        } else {
            try IERC20(tokenAddress).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
                console2.log("Vault Token Balance:", vaultBalance);
            } catch {
                console2.log("Vault Token Balance: Unable to fetch");
            }
            
            try vault.totalBalances(tokenAddress) returns (uint256 trackedTokens) {
                console2.log("Vault Tracked Tokens:", trackedTokens);
            } catch {
                console2.log("Vault Tracked Tokens: Unable to fetch");
            }
        }
        
        // Check payment-specific balance
        try vault.byPayment(paymentId, tokenAddress) returns (uint256 paymentBalance) {
            console2.log("Current Payment Balance:", paymentBalance);
        } catch {
            console2.log("Current Payment Balance: Unable to fetch");
        }
        
        vm.startBroadcast(payerKey);
        
        console2.log("\n=== Executing Vault Payment ===");
        
        if (tokenAddress == address(0)) {
            // Pay ETH via vault.payDirect()
            console2.log("Calling vault.payDirect() with ETH...");
            vault.payDirect{value: amount}(paymentId, address(0), amount);
            console2.log("ETH payment via vault completed!");
        } else {
            // Pay ERC20 tokens via vault.payDirect()
            console2.log("Calling vault.payDirect() with tokens...");
            
            // First approve tokens if needed
            IERC20 token = IERC20(tokenAddress);
            uint256 currentAllowance = token.allowance(payerAddress, vaultAddress);
            
            if (currentAllowance < amount) {
                console2.log("Approving tokens for vault...");
                bool approveSuccess = token.approve(vaultAddress, amount);
                require(approveSuccess, "Token approval failed");
                console2.log("Token approval successful!");
            }
            
            vault.payDirect(paymentId, tokenAddress, amount);
            console2.log("Token payment via vault completed!");
        }
        
        vm.stopBroadcast();
        
        // Post-payment verification
        console2.log("\n=== Post-Payment Verification ===");
        
        // Check vault balances after payment
        if (tokenAddress == address(0)) {
            console2.log("Vault New ETH Balance:", vaultAddress.balance);
            try vault.totalBalances(address(0)) returns (uint256 newTrackedEth) {
                console2.log("Vault New Tracked ETH:", newTrackedEth);
            } catch {
                console2.log("Vault New Tracked ETH: Unable to fetch");
            }
        } else {
            try IERC20(tokenAddress).balanceOf(vaultAddress) returns (uint256 newVaultBalance) {
                console2.log("Vault New Token Balance:", newVaultBalance);
            } catch {
                console2.log("Vault New Token Balance: Unable to fetch");
            }
            
            try vault.totalBalances(tokenAddress) returns (uint256 newTrackedTokens) {
                console2.log("Vault New Tracked Tokens:", newTrackedTokens);
            } catch {
                console2.log("Vault New Tracked Tokens: Unable to fetch");
            }
        }
        
        // Check payment-specific balance
        try vault.byPayment(paymentId, tokenAddress) returns (uint256 newPaymentBalance) {
            console2.log("New Payment Balance:", newPaymentBalance);
            console2.log("Payment Recorded:", newPaymentBalance >= amount ? "YES" : "PARTIAL/NO");
        } catch {
            console2.log("New Payment Balance: Unable to fetch");
        }
        
        console2.log("\n=== Summary ===");
        console2.log("Payment Method: Vault Contract Call");
        console2.log("Payment ID:", vm.toString(paymentId));
        console2.log("Vault Address:", vaultAddress);
        console2.log("Amount Sent:", amount);
        console2.log("Transaction completed successfully!");
        console2.log("Note: Payment is tracked by the vault and can be swept later.");
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

=== Pay with ETH (Native) via Vault ===
export VAULT_ADDRESS="0xdDFb667e2aC4B2F209b6D82e38133d1f36f6e0F4"
export PAYMENT_UUID="fa843d56-faae-42d4-aeba-34160a517668"
export TOKEN_ADDRESS="0x0000000000000000000000000000000000000000"
export AMOUNT="100000000000000000"  # 0.1 ETH in wei
export PRIVATE_KEY="your_private_key"

forge script script/PayInvoiceVault.s.sol:PayInvoiceVaultScript \
  --rpc-url $RPC_URL --broadcast

=== Pay with ERC20 Token via Vault ===
export VAULT_ADDRESS="0xdDFb667e2aC4B2F209b6D82e38133d1f36f6e0F4"
export PAYMENT_UUID="fa843d56-faae-42d4-aeba-34160a517668"
export TOKEN_ADDRESS="0xa0b86a33e6444e6644ca95bf4c2b7a3d0ef2ced0"  # Token contract address
export AMOUNT="1000000000000000000000"  # 1000 tokens (adjust for decimals)
export PRIVATE_KEY="your_private_key"

forge script script/PayInvoiceVault.s.sol:PayInvoiceVaultScript \
  --rpc-url $RPC_URL --broadcast

=== Alternative: Use Payment ID directly ===
export PAYMENT_ID="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
# ... other exports

=== Dry Run (No Broadcasting) ===
forge script script/PayInvoiceVault.s.sol:PayInvoiceVaultScript \
  --rpc-url $RPC_URL

Notes:
- Vault method automatically tracks payments and emits events
- For ERC20 tokens, approval is handled automatically if needed
- Use TOKEN_ADDRESS="0x0000000000000000000000000000000000000000" for ETH payments
- AMOUNT should be in wei for ETH, or token base units for ERC20
- This method integrates with the vault's payment tracking system
- Payments made this way can be swept later using the sweep functionality

Advantages of Vault Method:
- Automatic payment tracking and event emission
- Integration with vault's accounting system  
- Supports both ETH and ERC20 tokens
- Built-in safety checks and validations
- Can be swept/withdrawn later by authorized parties
*/
