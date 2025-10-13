// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

// Import the contract files
import {DeterministicVault} from "../contracts/DeterministicVault.sol";

contract DeployDeterministicVault is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY"); // deployer
        vm.startBroadcast(pk);

        // Deploy the vault (which now acts as its own factory)
        DeterministicVault vault = new DeterministicVault();
        console2.log("Vault (with built-in factory):", address(vault));

        vm.stopBroadcast();

        // For convenience in CI
        console2.log("EXPORT VAULT_ADDRESS=", address(vault));
    }
}