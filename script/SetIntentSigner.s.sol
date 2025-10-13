// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";

contract SetIntentSignerScript is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");
        address newIntentSigner = vm.envAddress("INTENT_SIGNER_ADDRESS");
        
        console2.log("=== Set Intent Signer Script ===");
        console2.log("Vault Address:", vaultAddress);
        console2.log("New Intent Signer:", newIntentSigner);
        
        DeterministicVault vault = DeterministicVault(payable(vaultAddress));
        
        // Check current state
        console2.log("\n=== Current Configuration ===");
        try vault.owner() returns (address owner) {
            console2.log("Vault Owner:", owner);
        } catch {
            console2.log("Vault Owner: Failed to fetch");
        }
        
        try vault.intentSigner() returns (address currentSigner) {
            console2.log("Current Intent Signer:", currentSigner);
            
            if (currentSigner == newIntentSigner) {
                console2.log("Intent signer is already set to the desired address!");
                return;
            }
        } catch {
            console2.log("Current Intent Signer: Failed to fetch");
        }
        
        vm.startBroadcast(deployerKey);
        
        console2.log("\n=== Setting Intent Signer ===");
        vault.setIntentSigner(newIntentSigner);
        console2.log("Transaction completed!");
        
        vm.stopBroadcast();
        
        // Verify the change
        console2.log("\n=== Verification ===");
        try vault.intentSigner() returns (address updatedSigner) {
            console2.log("Updated Intent Signer:", updatedSigner);
            
            if (updatedSigner == newIntentSigner) {
                console2.log("SUCCESS: Intent signer updated successfully!");
            } else {
                console2.log("ERROR: Intent signer was not updated correctly!");
            }
        } catch {
            console2.log("ERROR: Failed to verify intent signer change");
        }
    }
}

/*
Usage:
export VAULT_ADDRESS="0x742d35Cc6343C4532C6bae98abCCEa05e00AB0bC"
export INTENT_SIGNER_ADDRESS="0x1234567890123456789012345678901234567890"
export PRIVATE_KEY="your_private_key"  # Must be vault owner's private key

forge script script/SetIntentSigner.s.sol:SetIntentSignerScript \
  --rpc-url $RPC_URL --broadcast --verify

# Dry run first (recommended):
forge script script/SetIntentSigner.s.sol:SetIntentSignerScript \
  --rpc-url $RPC_URL

Note: Only the vault owner can set the intent signer address.
*/
