// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {DeterministicVault} from "../contracts/DeterministicVault.sol";
import {PaymentWallet} from "../contracts/PaymentWallet.sol";

contract UpgradeContracts is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address proxyAddress = vm.envAddress("PROXY_ADDRESS");
        address newImplementation = vm.envAddress("NEW_IMPLEMENTATION");

        vm.startBroadcast(deployerPrivateKey);

        // Upgrade the proxy to the new implementation
        ITransparentUpgradeableProxy(proxyAddress).upgradeToAndCall(newImplementation, "");

        console.log("Proxy at", proxyAddress, "upgraded to implementation at", newImplementation);

        vm.stopBroadcast();
    }
}
