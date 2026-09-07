// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.36;

import {Script} from "forge-std/Script.sol";
import {ERC5564Announcer} from "src/ERC5564Announcer.sol";

contract ERC5564AnnouncerScript is Script {
    ERC5564Announcer public erc5564Announcer;

    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);

        erc5564Announcer = new ERC5564Announcer();

        vm.stopBroadcast();
    }
}
