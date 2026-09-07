// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.36;

import {Test, Vm} from "forge-std/Test.sol";
import {ChaChaRngOffchain} from "frost-secp256k1-evm/utils/cryptography/ChaChaRngOffchain.sol";
import {Secp256k1} from "frost-secp256k1-evm/utils/cryptography/Secp256k1.sol";
import {ERC5564Announcer} from "src/ERC5564Announcer.sol";
import {IERC5564Announcer} from "src/IERC5564Announcer.sol";

contract ERC5564AnnouncerTest is Test {
    ERC5564Announcer public erc5564Announcer;

    function setUp() public {
        erc5564Announcer = new ERC5564Announcer();
    }

    function test_Announce() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);

        uint256 schemeId = 1;
        address stealthAddress = makeAddr("stealthAddress");
        // casting to 'uint8' is safe because [explain why]
        // forge-lint: disable-next-item(unsafe-typecast)
        bytes memory ephemeralPubKey =
            abi.encodePacked(uint8(Secp256k1.yCompressed(wallet.publicKeyY)), wallet.publicKeyX);
        bytes memory metadata = hex"ff";

        vm.expectEmit(address(erc5564Announcer));
        // forge-lint: disable-next-item(reentrancy-events)
        emit IERC5564Announcer.Announcement(schemeId, stealthAddress, address(this), ephemeralPubKey, metadata);

        erc5564Announcer.announce(schemeId, stealthAddress, ephemeralPubKey, metadata);
    }
}
