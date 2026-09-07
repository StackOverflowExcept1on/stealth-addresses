// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.36;

import {Test} from "forge-std/Test.sol";
import {ERC6538RegistryScript} from "script/ERC6538Registry.s.sol";

contract ERC6538RegistryScriptTest is Test {
    function test_Upgrade() public {
        /// forge-lint: disable-next-line(unsafe-cheatcode)
        vm.setEnv("PRIVATE_KEY", "1");
        ERC6538RegistryScript erc6538RegistryScript = new ERC6538RegistryScript();
        erc6538RegistryScript.run();
    }
}
