// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.35;

import {Script} from "forge-std/Script.sol";
import {ERC5564AnnouncerWithHooks} from "src/ERC5564AnnouncerWithHooks.sol";

contract ERC5564AnnouncerWithHooksScript is Script {
    ERC5564AnnouncerWithHooks public erc5564AnnouncerWithHooks;

    function setUp() public {}

    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        erc5564AnnouncerWithHooks = new ERC5564AnnouncerWithHooks();

        vm.stopBroadcast();
    }
}
