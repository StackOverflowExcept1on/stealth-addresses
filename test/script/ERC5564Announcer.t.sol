// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC5564AnnouncerScript} from "script/ERC5564Announcer.s.sol";

contract ERC5564AnnouncerScriptTest is Test {
    function setUp() public {}

    function test_Upgrade() public {
        /// forge-lint: disable-next-line(unsafe-cheatcode)
        vm.setEnv("PRIVATE_KEY", "1");
        ERC5564AnnouncerScript erc5564AnnouncerScript = new ERC5564AnnouncerScript();
        erc5564AnnouncerScript.setUp();
        erc5564AnnouncerScript.run();
    }
}
