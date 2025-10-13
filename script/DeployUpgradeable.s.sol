// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";
import {PaymentWallet} from "../contracts/PaymentWallet.sol";
import {DeterministicVaultProxy} from "../contracts/proxy/DeterministicVaultProxy.sol";
import {PaymentWalletProxy} from "../contracts/proxy/PaymentWalletProxy.sol";

contract DeployUpgradeable is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy implementation contracts
        DeterministicVault vaultImpl = new DeterministicVault();
        PaymentWallet walletImpl = new PaymentWallet();

        // Initialize implementation contracts to prevent selfdestruct attacks
        // This will revert as expected, but that's fine
        try vaultImpl.initialize() {} catch {}
        try walletImpl.initialize(address(0)) {} catch {}

        // Prepare initialization data
        bytes memory vaultData = abi.encodeWithSelector(
            DeterministicVault.initialize.selector
        );

        // Deploy proxy with implementation
        DeterministicVaultProxy vaultProxy = new DeterministicVaultProxy(
            address(vaultImpl),
            vaultData
        );

        // Log the addresses
        console.log("DeterministicVault implementation deployed at:", address(vaultImpl));
        console.log("PaymentWallet implementation deployed at:", address(walletImpl));
        console.log("DeterministicVaultProxy deployed at:", address(vaultProxy));

        vm.stopBroadcast();
    }
}
