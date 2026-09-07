// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.36;

import {Test, Vm} from "forge-std/Test.sol";
import {Memory} from "frost-secp256k1-evm/utils/Memory.sol";
import {ChaChaRngOffchain} from "frost-secp256k1-evm/utils/cryptography/ChaChaRngOffchain.sol";
import {Secp256k1Arithmetic} from "frost-secp256k1-evm/utils/cryptography/Secp256k1Arithmetic.sol";
import {ERC5564AnnouncerWithHooks} from "src/ERC5564AnnouncerWithHooks.sol";
import {IERC5564Announcer} from "src/IERC5564Announcer.sol";

contract ERC5564AnnouncerWithHooksTest is Test {
    ERC5564AnnouncerWithHooks public erc5564AnnouncerWithHooks;

    function setUp() public {
        erc5564AnnouncerWithHooks = new ERC5564AnnouncerWithHooks();
    }

    function test_Announce() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        uint256 memPtr = Memory.allocate(96);

        uint256 schemeId = 1;
        address stealthAddress = makeAddr("stealthAddress");
        bytes memory ephemeralPubKey =
            Secp256k1Arithmetic.compressAffinePoint(memPtr, wallet.publicKeyX, wallet.publicKeyY);
        bytes memory metadata = hex"ff";

        vm.expectEmit(address(erc5564AnnouncerWithHooks));
        // forge-lint: disable-next-item(reentrancy-events)
        emit IERC5564Announcer.Announcement(schemeId, stealthAddress, address(this), ephemeralPubKey, metadata);

        erc5564AnnouncerWithHooks.announce(schemeId, stealthAddress, ephemeralPubKey, metadata);
    }

    function test_AnnounceWithInvalidEphemeralPubKey() public {
        uint256 schemeId = 1;
        address stealthAddress = makeAddr("stealthAddress");
        bytes memory ephemeralPubKey = "";
        bytes memory metadata = hex"ff";

        vm.expectRevert();
        erc5564AnnouncerWithHooks.announce(schemeId, stealthAddress, ephemeralPubKey, metadata);
    }

    function test_AnnounceWithInvalidMetadata() public {
        uint256 scalar = ChaChaRngOffchain.randomNonZeroScalar();
        Vm.Wallet memory wallet = vm.createWallet(scalar);
        uint256 memPtr = Memory.allocate(96);

        uint256 schemeId = 1;
        address stealthAddress = makeAddr("stealthAddress");
        bytes memory ephemeralPubKey =
            Secp256k1Arithmetic.compressAffinePoint(memPtr, wallet.publicKeyX, wallet.publicKeyY);
        bytes memory metadata = "";

        vm.expectRevert();
        erc5564AnnouncerWithHooks.announce(schemeId, stealthAddress, ephemeralPubKey, metadata);
    }
}
