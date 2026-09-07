// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.36;

import {Script} from "forge-std/Script.sol";
import {ERC6538Registry} from "src/ERC6538Registry.sol";

contract ERC6538RegistryScript is Script {
    ERC6538Registry public erc6538Registry;

    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        erc6538Registry = new ERC6538Registry();

        vm.stopBroadcast();
    }
}
