// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";

contract WhitelistTokenScript is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");
        address tokenAddress = vm.envAddress("TOKEN_ADDRESS");
        bool allowed = vm.envBool("ALLOWED");
        
        console2.log("=== Whitelist Token Script ===");
        console2.log("Vault Address:", vaultAddress);
        console2.log("Token Address:", tokenAddress);
        console2.log("Action:", allowed ? "WHITELIST" : "REMOVE");
        
        // Get token info safely
        console2.log("Token Symbol:", _getTokenSymbol(tokenAddress));
        console2.log("Token Name:", _getTokenName(tokenAddress));
        console2.log("Token Decimals:", _getTokenDecimals(tokenAddress));
        
        vm.startBroadcast(deployerKey);
        
        DeterministicVault vault = DeterministicVault(payable(vaultAddress));
        bool currentStatus = vault.tokenWhitelist(tokenAddress);
        console2.log("Current Whitelist Status:", currentStatus);
        
        if (currentStatus == allowed) {
            console2.log("Token already has the desired whitelist status!");
            vm.stopBroadcast();
            return;
        }
        
        vault.setWhitelist(tokenAddress, allowed);
        console2.log("Transaction completed!");
        
        vm.stopBroadcast();
        
        bool newStatus = vault.tokenWhitelist(tokenAddress);
        console2.log("Verified New Status:", newStatus);
        console2.log(newStatus == allowed ? "SUCCESS!" : "ERROR!");
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
Usage:
export VAULT_ADDRESS="0x742d35Cc6343C4532C6bae98abCCEa05e00AB0bC"
export TOKEN_ADDRESS="0xa0b86a33e6444e6644ca95bf4c2b7a3d0ef2ced0"
export ALLOWED="true"  # or "false" to remove from whitelist
export PRIVATE_KEY="your_private_key"

forge script script/WhitelistToken.s.sol:WhitelistTokenScript \
  --rpc-url $RPC_URL --broadcast --verify
*/