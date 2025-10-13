// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";

contract ReadVaultDataScript is Script {
    struct TokenInfo {
        address tokenAddress;
        string symbol;
        string name;
        uint8 decimals;
        uint256 vaultBalance;
        uint256 totalTracked;
        bool isWhitelisted;
    }
    
    function run() external view {
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");
        
        console2.log("=== DeterministicVault Data Reader ===");
        console2.log("Vault Address:", vaultAddress);
        console2.log("Block Number:", block.number);
        
        DeterministicVault vault = DeterministicVault(payable(vaultAddress));
        
        // Basic vault info
        console2.log("\n=== Vault Configuration ===");
        try vault.owner() returns (address owner) {
            console2.log("Owner:", owner);
        } catch {
            console2.log("Owner: Failed to fetch");
        }
        
        try vault.intentSigner() returns (address signer) {
            console2.log("Intent Signer:", signer);
        } catch {
            console2.log("Intent Signer: Failed to fetch");
        }
        
        // Native balance
        console2.log("\n=== Native Balance ===");
        uint256 ethBalance = vaultAddress.balance;
        console2.log("Vault Native Balance:", ethBalance);
        
        try vault.totalBalances(address(0)) returns (uint256 ethTracked) {
            console2.log("Native Total Tracked:", ethTracked);
        } catch {
            console2.log("Native Total Tracked: Failed to fetch");
        }
        
        // Get specific tokens from environment (optional)
        console2.log("\n=== Token Analysis ===");
        string memory tokensEnv;
        try vm.envString("TOKEN_ADDRESSES") returns (string memory tokens) {
            tokensEnv = tokens;
            console2.log("Custom tokens provided:", tokensEnv);
            console2.log("(Note: For multiple tokens, parse manually)");
        } catch {
            console2.log("No custom tokens specified");
        }
        
        // Analyze sample addresses or provided token
        address tokenToCheck;
        try vm.envAddress("TOKEN_ADDRESS") returns (address token) {
            tokenToCheck = token;
            console2.log("Analyzing specific token:", tokenToCheck);
            
            TokenInfo memory info = _getTokenInfo(vault, tokenToCheck);
            _printTokenInfo(info);
        } catch {
            console2.log("No specific token provided for analysis");
        }
        
        // EIP-712 info
        console2.log("\n=== EIP-712 Info ===");
        try vault.domainSeparator() returns (bytes32 domain) {
            console2.log("Domain Separator:", vm.toString(domain));
        } catch {
            console2.log("Domain Separator: Failed to fetch");
        }
        
        console2.log("\n=== Summary ===");
        console2.log("Vault Native Balance:", ethBalance);
        console2.log("Analysis complete!");
    }
    
    function _getTokenInfo(DeterministicVault vault, address tokenAddr) internal view returns (TokenInfo memory info) {
        info.tokenAddress = tokenAddr;
        info.symbol = _getTokenSymbol(tokenAddr);
        info.name = _getTokenName(tokenAddr);
        info.decimals = _getTokenDecimals(tokenAddr);
        
        try IERC20(tokenAddr).balanceOf(address(vault)) returns (uint256 balance) {
            info.vaultBalance = balance;
        } catch {
            info.vaultBalance = 0;
        }
        
        try vault.totalBalances(tokenAddr) returns (uint256 tracked) {
            info.totalTracked = tracked;
        } catch {
            info.totalTracked = 0;
        }
        
        try vault.tokenWhitelist(tokenAddr) returns (bool whitelisted) {
            info.isWhitelisted = whitelisted;
        } catch {
            info.isWhitelisted = false;
        }
    }
    
    function _printTokenInfo(TokenInfo memory info) internal pure {
        console2.log("--- Token Info ---");
        console2.log("Address:", info.tokenAddress);
        console2.log("Symbol:", info.symbol);
        console2.log("Name:", info.name);
        console2.log("Decimals:", info.decimals);
        console2.log("Vault Balance:", info.vaultBalance);
        console2.log("Total Tracked:", info.totalTracked);
        console2.log("Whitelisted:", info.isWhitelisted);
        
        if (info.vaultBalance != info.totalTracked) {
            if (info.vaultBalance > info.totalTracked) {
                console2.log("Untracked Balance:", info.vaultBalance - info.totalTracked);
            } else {
                console2.log("Negative Tracking:", info.totalTracked - info.vaultBalance);
            }
        }
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
Usage (read-only, no broadcast needed):
export VAULT_ADDRESS="0x742d35Cc6343C4532C6bae98abCCEa05e00AB0bC"

# Optional: analyze specific token
export TOKEN_ADDRESS="0xa0b86a33e6444e6644ca95bf4c2b7a3d0ef2ced0"

forge script script/ReadVaultData.s.sol:ReadVaultDataScript \
  --rpc-url $RPC_URL
*/