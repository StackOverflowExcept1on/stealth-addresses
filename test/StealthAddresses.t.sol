// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.36;

import {Test, console} from "forge-std/Test.sol";
import {Memory} from "frost-secp256k1-evm/utils/Memory.sol";
import {ChaChaRngOffchain} from "frost-secp256k1-evm/utils/cryptography/ChaChaRngOffchain.sol";
import {Secp256k1} from "frost-secp256k1-evm/utils/cryptography/Secp256k1.sol";
import {Secp256k1Arithmetic} from "frost-secp256k1-evm/utils/cryptography/Secp256k1Arithmetic.sol";
import {ERC5564AnnouncerWithHooks} from "src/ERC5564AnnouncerWithHooks.sol";
import {ERC6538Registry} from "src/ERC6538Registry.sol";
import {IERC5564Announcer} from "src/IERC5564Announcer.sol";
import {IERC6538Registry} from "src/IERC6538Registry.sol";
import {StealthAddresses} from "src/StealthAddresses.sol";

contract StealthAddressesTest is Test {
    address public sender;
    address public recipient;
    address public newRecipient;
    IERC6538Registry public erc6538Registry;
    IERC5564Announcer public erc5564Announcer;

    function setUp() public {
        sender = makeAddr("Sender");
        recipient = makeAddr("Recipient");
        newRecipient = makeAddr("NewRecipient");

        vm.deal(sender, 1 ether);

        erc6538Registry = new ERC6538Registry();
        erc5564Announcer = new ERC5564AnnouncerWithHooks();
    }

    /// forge-config: default.fuzz.seed = "0x4242424242424242424242424242424242424242424242424242424242424242"
    function test_StealthAddresses() public {
        uint256 memPtr1 = Memory.allocate(192); // 96 * 2 bytes for two points
        uint256 memPtr2;
        unchecked {
            memPtr2 = memPtr1 + 96;
        }
        uint256 memPtr3 = Memory.allocate(192);

        console.log("Sender");
        console.logAddress(sender);
        console.log();

        console.log("Recipient");
        console.logAddress(recipient);
        console.log();

        // Recipient has access to the private keys $p_{spend}$, $p_{view}$ from which public keys $P_{spend}$ and $P_{view}$ are derived.
        console.log("Recipient generates keys...");
        console.log();

        // $p_{spend}$
        uint256 spendPrivKey = ChaChaRngOffchain.randomNonZeroScalar();
        console.log("Spending Private Key:");
        console.logBytes32(bytes32(spendPrivKey));
        console.log();

        // $P_{spend}$
        (uint256 spendPubKeyX, uint256 spendPubKeyY) =
            Secp256k1Arithmetic.mulAffinePoint(memPtr3, Secp256k1.GX, Secp256k1.GY, spendPrivKey);
        bytes memory spendPubKey = Secp256k1Arithmetic.compressAffinePoint(memPtr1, spendPubKeyX, spendPubKeyY);

        console.log("Spending Public Key (uncompressed):");
        console.logBytes32(bytes32(spendPubKeyX));
        console.logBytes32(bytes32(spendPubKeyY));
        console.log();

        console.log("Spending Public Key (compressed):");
        console.logBytes(spendPubKey);
        console.log();

        // $p_{view}$
        uint256 viewPrivKey = ChaChaRngOffchain.randomNonZeroScalar();
        console.log("Viewing Private Key:");
        console.logBytes32(bytes32(viewPrivKey));
        console.log();

        // $P_{view}$
        (uint256 viewPubKeyX, uint256 viewPubKeyY) =
            Secp256k1Arithmetic.mulAffinePoint(memPtr3, Secp256k1.GX, Secp256k1.GY, viewPrivKey);
        bytes memory viewPubKey = Secp256k1Arithmetic.compressAffinePoint(memPtr2, viewPubKeyX, viewPubKeyY);

        console.log("Viewing Public Key (uncompressed):");
        console.logBytes32(bytes32(viewPubKeyX));
        console.logBytes32(bytes32(viewPubKeyY));
        console.log();

        console.log("Viewing Public Key (compressed):");
        console.logBytes(viewPubKey);
        console.log();

        // Recipient has published a stealth meta-address that consists of the public keys $P_{spend}$ and $P_{view}$.
        vm.startPrank(recipient);

        // `st:<chain>:0x<compressed spendPk><compressed viewPk>`
        // https://github.com/ethereum-lists/chains
        // forge-lint: disable-next-item(encode-packed-collision)
        bytes memory stealthMetaAddress = abi.encodePacked(spendPubKey, viewPubKey);
        console.log("Stealth Meta-Address:");
        console.log("st:eth:");
        console.logBytes(stealthMetaAddress);
        console.log();

        uint256 schemeId = 1;

        vm.expectEmit(address(erc6538Registry));
        // forge-lint: disable-next-item(reentrancy-events)
        emit IERC6538Registry.StealthMetaAddressSet(recipient, schemeId, stealthMetaAddress);

        erc6538Registry.registerKeys(schemeId, stealthMetaAddress);

        vm.stopPrank();

        // Generate a random 32-byte entropy ephemeral private key $p_{ephemeral}$
        console.log("Sender generates keys...");
        console.log();

        uint256 ephemeralPrivKey = ChaChaRngOffchain.randomNonZeroScalar();
        console.log("Ephemeral Private Key:");
        console.logBytes32(bytes32(ephemeralPrivKey));
        console.log();

        // Sender passes the stealth meta-address to the `generateStealthAddress` function.
        stealthMetaAddress = erc6538Registry.stealthMetaAddressOf(recipient, schemeId);
        (address stealthAddress, bytes memory ephemeralPubKey, bytes1 viewTag) =
            StealthAddresses.generateStealthAddress(ephemeralPrivKey, stealthMetaAddress);

        vm.label(stealthAddress, "Recipient's stealth address");

        console.log("Stealth Address:");
        console.logAddress(stealthAddress);
        console.log();

        console.log("Ephemeral Public Key (compressed):");
        console.logBytes(ephemeralPubKey);
        console.log();

        console.log("View Tag:");
        console.logBytes1(viewTag);
        console.log();

        bytes memory metadata = abi.encodePacked(viewTag);

        vm.startPrank(sender);

        vm.expectEmit(address(erc5564Announcer));
        // forge-lint: disable-next-item(reentrancy-events)
        emit IERC5564Announcer.Announcement(schemeId, stealthAddress, sender, ephemeralPubKey, metadata);

        erc5564Announcer.announce(schemeId, stealthAddress, ephemeralPubKey, metadata);

        // forge-lint: disable-next-item(arbitrary-send-eth, low-level-calls)
        (bool success,) = stealthAddress.call{value: 1 ether}("");
        require(success);

        vm.stopPrank();

        assertEq(stealthAddress.balance, 1 ether);
        assertEq(sender.balance, 0 ether);

        bytes memory viewingKey = abi.encodePacked(viewPrivKey);
        bytes memory spendingPubKey = spendPubKey;
        assertTrue(
            StealthAddresses.checkStealthAddress(stealthAddress, ephemeralPubKey, metadata, viewingKey, spendingPubKey)
        );

        bytes memory spendingKey = abi.encodePacked(spendPrivKey);
        (bytes memory stealthKey) =
            StealthAddresses.computeStealthKey(stealthAddress, ephemeralPubKey, viewingKey, spendingKey);

        uint256 memPtr4;
        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            memPtr4 := add(stealthKey, 0x20)
        }
        uint256 stealthPrivKey = Memory.readWord(memPtr4, 0x00);
        assertEq(vm.addr(stealthPrivKey), stealthAddress);

        vm.startPrank(stealthAddress);

        // forge-lint: disable-next-item(arbitrary-send-eth, low-level-calls)
        (success,) = newRecipient.call{value: 1 ether}("");
        require(success);

        vm.stopPrank();

        assertEq(newRecipient.balance, 1 ether);
        assertEq(stealthAddress.balance, 0 ether);
    }
}
