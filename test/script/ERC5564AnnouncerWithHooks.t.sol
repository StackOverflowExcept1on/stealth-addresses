// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.35;

import {Test} from "forge-std/Test.sol";
import {ERC5564AnnouncerWithHooksScript} from "script/ERC5564AnnouncerWithHooks.s.sol";

contract ERC5564AnnouncerWithHooksScriptTest is Test {
    function setUp() public {}

    function test_Upgrade() public {
        /// forge-lint: disable-next-line(unsafe-cheatcode)
        vm.setEnv("PRIVATE_KEY", "1");
        ERC5564AnnouncerWithHooksScript erc5564AnnouncerWithHooksScript = new ERC5564AnnouncerWithHooksScript();
        erc5564AnnouncerWithHooksScript.setUp();
        erc5564AnnouncerWithHooksScript.run();
    }
}
