// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";

contract SweepAddressScript is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");

        bytes32 paymentId;
        try vm.envBytes32("PAYMENT_ID") returns (bytes32 id) {
            paymentId = id;
        } catch {
            string memory uuidString = vm.envString("PAYMENT_UUID");
            paymentId = DeterministicVault(payable(vaultAddress)).paymentIdFromUuid(uuidString);
        }

        address tokenAddress = vm.envAddress("TOKEN_ADDRESS");
        address payerAddress = vm.envAddress("PAYER_ADDRESS");

        console2.log("=== Sweep Address Script ===");
        console2.log("Vault Address:", vaultAddress);
        console2.log("Payment ID:", vm.toString(paymentId));
        console2.log("Token Address:", tokenAddress);
        console2.log("Payer Address:", payerAddress);

        DeterministicVault vault = DeterministicVault(payable(vaultAddress));
        address walletAddress = vault.walletAddress(paymentId);
        console2.log("Wallet Address to Sweep:", walletAddress);

        // Check balances before sweep
        console2.log("\n=== Pre-Sweep Balances ===");
        if (tokenAddress == address(0)) {
            console2.log("Wallet ETH Balance:", walletAddress.balance);
            console2.log("Vault ETH Balance:", vaultAddress.balance);
        } else {
            try IERC20(tokenAddress).balanceOf(walletAddress) returns (uint256 walletBalance) {
                console2.log("Wallet Token Balance:", walletBalance);
            } catch {
                console2.log("Failed to get wallet token balance");
            }

            try IERC20(tokenAddress).balanceOf(vaultAddress) returns (uint256 vaultBalance) {
                console2.log("Vault Token Balance:", vaultBalance);
            } catch {
                console2.log("Failed to get vault token balance");
            }

            console2.log("Token Symbol:", _getTokenSymbol(tokenAddress));
        }

        vm.startBroadcast(deployerKey);

        console2.log("\n=== Executing Sweep ===");
        address deployedWallet = vault.sweep(paymentId, tokenAddress, payerAddress);
        console2.log("Sweep completed! Deployed Wallet:", deployedWallet);

        vm.stopBroadcast();

        // Verify deployment
        uint256 codeSize;
        assembly { codeSize := extcodesize(deployedWallet) }
        console2.log(codeSize > 0 ? "SUCCESS: Wallet deployed!" : "WARNING: Deployment may have failed!");
    }

    function _getTokenSymbol(address token) internal view returns (string memory) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("symbol()"));
        return success && data.length > 0 ? abi.decode(data, (string)) : "UNKNOWN";
    }
}

/*
Usage:
export VAULT_ADDRESS="0x742d35Cc6343C4532C6bae98abCCEa05e00AB0bC"
export PAYMENT_UUID="550e8400-e29b-41d4-a716-446655440000"  # or use PAYMENT_ID
export TOKEN_ADDRESS="0x0000000000000000000000000000000000000000"  # ETH, or token address
export PAYER_ADDRESS="0x742d35Cc6343C4532C6bae98abCCEa05e00AB0bC"
export PRIVATE_KEY="your_private_key"

forge script script/SweepAddress.s.sol:SweepAddressScript \
  --rpc-url $RPC_URL --broadcast --verify
*/
