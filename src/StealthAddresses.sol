// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.36;

import {Memory} from "frost-secp256k1-evm/utils/Memory.sol";
import {ChaChaRngOffchain} from "frost-secp256k1-evm/utils/cryptography/ChaChaRngOffchain.sol";
import {ECDSA} from "frost-secp256k1-evm/utils/cryptography/ECDSA.sol";
import {Hashes} from "frost-secp256k1-evm/utils/cryptography/Hashes.sol";
import {Secp256k1} from "frost-secp256k1-evm/utils/cryptography/Secp256k1.sol";
import {Secp256k1Arithmetic} from "frost-secp256k1-evm/utils/cryptography/Secp256k1Arithmetic.sol";

/**
 * @dev Library for interacting with stealth addresses, which are defined in ERC-5564.
 * @dev See ERC-5564 for more details:
 *      - https://eips.ethereum.org/EIPS/eip-5564
 */
library StealthAddresses {
    /**
     * @notice Generates a stealth address from a stealth meta address.
     * @param stealthMetaAddress The recipient's stealth meta-address.
     * @return stealthAddress The recipient's stealth address.
     * @return ephemeralPubKey The ephemeral public key used to generate the stealth address.
     * @return viewTag The view tag derived from the shared secret.
     */
    function generateStealthAddress(bytes memory stealthMetaAddress)
        internal
        view
        returns (address stealthAddress, bytes memory ephemeralPubKey, bytes1 viewTag)
    {
        uint256 ephemeralPrivKey = ChaChaRngOffchain.randomNonZeroScalar();
        (stealthAddress, ephemeralPubKey, viewTag) = generateStealthAddress(ephemeralPrivKey, stealthMetaAddress);
    }

    /**
     * @notice Generates a stealth address from a stealth meta address.
     * @param ephemeralPrivKey The ephemeral private key used to generate the stealth address.
     * @param stealthMetaAddress The recipient's stealth meta-address.
     * @return stealthAddress The recipient's stealth address.
     * @return ephemeralPubKey The ephemeral public key used to generate the stealth address.
     * @return viewTag The view tag derived from the shared secret.
     */
    function generateStealthAddress(uint256 ephemeralPrivKey, bytes memory stealthMetaAddress)
        internal
        view
        returns (address stealthAddress, bytes memory ephemeralPubKey, bytes1 viewTag)
    {
        // The `generateStealthAddress` function performs the following computations:
        uint256 memPtr1 = Memory.allocate(96);
        uint256 memPtr2 = Memory.allocate(192);

        // Derive the ephemeral public key $P_{ephemeral}$ from $p_{ephemeral}$.
        (uint256 ephemeralPubKeyX, uint256 ephemeralPubKeyY) =
            Secp256k1Arithmetic.mulAffinePoint(memPtr2, Secp256k1.GX, Secp256k1.GY, ephemeralPrivKey);
        ephemeralPubKey = Secp256k1Arithmetic.compressAffinePoint(memPtr1, ephemeralPubKeyX, ephemeralPubKeyY);

        // Parse the spending and viewing public keys, $P_{spend}$ and $P_{view}$, from the stealth meta-address.
        // forge-lint: disable-next-item(custom-errors)
        require(stealthMetaAddress.length == 66);

        uint8 spendPubKeyCompressedY;
        uint256 spendPubKeyX;
        uint256 spendPubKeyY;

        uint8 viewPubKeyCompressedY;
        uint256 viewPubKeyX;
        uint256 viewPubKeyY;

        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            spendPubKeyCompressedY := byte(0, mload(add(stealthMetaAddress, 0x20)))
            spendPubKeyX := mload(add(stealthMetaAddress, 0x21))

            viewPubKeyCompressedY := byte(0, mload(add(stealthMetaAddress, 0x41)))
            viewPubKeyX := mload(add(stealthMetaAddress, 0x42))
        }

        (, spendPubKeyY) = Secp256k1Arithmetic.decompressToAffinePoint(memPtr2, spendPubKeyX, spendPubKeyCompressedY);
        (, viewPubKeyY) = Secp256k1Arithmetic.decompressToAffinePoint(memPtr2, viewPubKeyX, viewPubKeyCompressedY);

        // A shared secret $s$ is computed as $s = p_{ephemeral} \cdot P_{view}$.
        (uint256 sharedSecretX,) =
            Secp256k1Arithmetic.mulAffinePoint(memPtr2, viewPubKeyX, viewPubKeyY, ephemeralPrivKey);

        // The secret is hashed $s_{h} = \textrm{h}(s)$.
        uint256 sharedSecretXHashed = Hashes.efficientKeccak256(sharedSecretX) % Secp256k1.N;
        // forge-lint: disable-next-item(custom-errors)
        require(sharedSecretXHashed != 0);

        // The view tag $v$ is extracted by taking the most significant byte $s_{h}[0]$.
        // casting to 'uint8' is safe because we just want to extract most significant byte
        // forge-lint: disable-next-line(unsafe-typecast)
        viewTag = bytes1(uint8(sharedSecretXHashed >> 248));

        // Multiply the hashed shared secret with the generator point $S_h = s_h \cdot G$.
        (
            uint256 sharedSecretXHashedPubKeyXProjective,
            uint256 sharedSecretXHashedPubKeyYProjective,
            uint256 sharedSecretXHashedPubKeyZProjective
        ) = Secp256k1Arithmetic.mulAffinePointAsProjective(Secp256k1.GX, Secp256k1.GY, sharedSecretXHashed);

        // The recipient's stealth public key is computed as $P_{stealth} = P_{spend} + S_h$.
        (uint256 spendPubKeyXProjective, uint256 spendPubKeyYProjective, uint256 spendPubKeyZProjective) =
            Secp256k1Arithmetic.convertAffinePointToProjectivePoint(spendPubKeyX, spendPubKeyY);
        (uint256 stealthPubKeyXProjective, uint256 stealthPubKeyYProjective, uint256 stealthPubKeyZProjective) = Secp256k1Arithmetic.addProjectivePoint(
            spendPubKeyXProjective,
            spendPubKeyYProjective,
            spendPubKeyZProjective,
            sharedSecretXHashedPubKeyXProjective,
            sharedSecretXHashedPubKeyYProjective,
            sharedSecretXHashedPubKeyZProjective
        );
        (uint256 stealthPubKeyX, uint256 stealthPubKeyY) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(
            memPtr2, stealthPubKeyXProjective, stealthPubKeyYProjective, stealthPubKeyZProjective
        );

        // The recipient's stealth address $a_{stealth}$ is computed as $\textrm{pubkeyToAddress}(P_{stealth})$.
        // casting to 'uint8' is safe because [explain why]
        // forge-lint: disable-next-item(unsafe-typecast)
        stealthAddress = address(uint160(Secp256k1.toAddress(stealthPubKeyX, stealthPubKeyY)));
    }

    /// forge-lint: disable-next-item(internal-function-used-once)
    /**
     * @notice Returns true if funds sent to a stealth address belong to the recipient who controls
     *         the corresponding spending key.
     * @param stealthAddress The recipient's stealth address.
     * @param ephemeralPubKey The ephemeral public key used to generate the stealth address.
     * @param metadata The metadata associated with the announcement, including the view tag in the first byte.
     * @param viewingKey The recipient's viewing private key.
     * @param spendingPubKey The recipient's spending public key.
     * @return True if funds sent to the stealth address belong to the recipient.
     */
    function checkStealthAddress(
        address stealthAddress,
        bytes memory ephemeralPubKey,
        bytes memory metadata,
        bytes memory viewingKey,
        bytes memory spendingPubKey
    ) internal view returns (bool) {
        // The `checkStealthAddress` function performs the following computations:
        // forge-lint: disable-next-item(custom-errors)
        require(ephemeralPubKey.length == 33);

        uint8 ephemeralPubKeyCompressedY;
        uint256 ephemeralPubKeyX;
        uint256 ephemeralPubKeyY;

        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            ephemeralPubKeyCompressedY := byte(0, mload(add(ephemeralPubKey, 0x20)))
            ephemeralPubKeyX := mload(add(ephemeralPubKey, 0x21))
        }

        uint256 memPtr1 = Memory.allocate(192);
        (, ephemeralPubKeyY) =
            Secp256k1Arithmetic.decompressToAffinePoint(memPtr1, ephemeralPubKeyX, ephemeralPubKeyCompressedY);

        // forge-lint: disable-next-item(custom-errors)
        require(viewingKey.length == 32);

        uint256 viewPrivKey;
        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            viewPrivKey := mload(add(viewingKey, 0x20))
        }
        // forge-lint: disable-next-item(custom-errors)
        require(Secp256k1.isValidNonZeroScalar(viewPrivKey));

        // forge-lint: disable-next-item(custom-errors)
        require(spendingPubKey.length == 33);

        uint8 spendPubKeyCompressedY;
        uint256 spendPubKeyX;
        uint256 spendPubKeyY;

        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            spendPubKeyCompressedY := byte(0, mload(add(spendingPubKey, 0x20)))
            spendPubKeyX := mload(add(spendingPubKey, 0x21))
        }

        (, spendPubKeyY) = Secp256k1Arithmetic.decompressToAffinePoint(memPtr1, spendPubKeyX, spendPubKeyCompressedY);

        // forge-lint: disable-next-item(custom-errors)
        require(metadata.length >= 1);

        uint256 metadataViewTag;

        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            metadataViewTag := byte(0, mload(add(metadata, 0x20)))
        }

        // casting to 'uint8' is safe because we just want to extract most significant byte
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes1 expectedViewTag = bytes1(uint8(metadataViewTag));

        // Shared secret $s$ is computed by multiplying the viewing private key with the ephemeral public key of the announcement $s = p_{view}$ * $P_{ephemeral}$.
        (uint256 sharedSecretX,) =
            Secp256k1Arithmetic.mulAffinePoint(memPtr1, ephemeralPubKeyX, ephemeralPubKeyY, viewPrivKey);

        // The secret is hashed $s_{h} = h(s)$.
        uint256 sharedSecretXHashed = Hashes.efficientKeccak256(sharedSecretX) % Secp256k1.N;
        // forge-lint: disable-next-item(custom-errors)
        require(sharedSecretXHashed != 0);

        // The view tag $v$ is extracted by taking the most significant byte $s_{h}[0]$ and can be compared to the given view tag. If the view tags do not match, this `Announcement` is not for the user and the remaining steps can be skipped. If the view tags match, continue on.
        // casting to 'uint8' is safe because we just want to extract most significant byte
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes1 viewTag = bytes1(uint8(sharedSecretXHashed >> 248));
        if (viewTag != expectedViewTag) {
            return false;
        }

        // Multiply the hashed shared secret with the generator point $S_h = s_h \cdot G$.
        (
            uint256 sharedSecretXHashedPubKeyXProjective,
            uint256 sharedSecretXHashedPubKeyYProjective,
            uint256 sharedSecretXHashedPubKeyZProjective
        ) = Secp256k1Arithmetic.mulAffinePointAsProjective(Secp256k1.GX, Secp256k1.GY, sharedSecretXHashed);

        // The stealth public key is computed as $P_{stealth} = P_{spend} + S_h$.
        (uint256 spendPubKeyXProjective, uint256 spendPubKeyYProjective, uint256 spendPubKeyZProjective) =
            Secp256k1Arithmetic.convertAffinePointToProjectivePoint(spendPubKeyX, spendPubKeyY);
        (uint256 stealthPubKeyXProjective, uint256 stealthPubKeyYProjective, uint256 stealthPubKeyZProjective) = Secp256k1Arithmetic.addProjectivePoint(
            spendPubKeyXProjective,
            spendPubKeyYProjective,
            spendPubKeyZProjective,
            sharedSecretXHashedPubKeyXProjective,
            sharedSecretXHashedPubKeyYProjective,
            sharedSecretXHashedPubKeyZProjective
        );
        (uint256 stealthPubKeyX, uint256 stealthPubKeyY) = Secp256k1Arithmetic.convertProjectivePointToAffinePoint(
            memPtr1, stealthPubKeyXProjective, stealthPubKeyYProjective, stealthPubKeyZProjective
        );

        // The derived stealth address $a_{stealth}$ is computed as $\textrm{pubkeyToAddress}(P_{stealth})$.
        // casting to 'uint8' is safe because [explain why]
        // forge-lint: disable-next-item(unsafe-typecast)
        address derivedStealthAddress = address(uint160(Secp256k1.toAddress(stealthPubKeyX, stealthPubKeyY)));

        // Return `true` if the stealth address of the announcement matches the derived stealth address, else return `false`.
        return stealthAddress == derivedStealthAddress;
    }

    /// forge-lint: disable-next-item(internal-function-used-once)
    /**
     * @notice Computes the stealth private key for a stealth address.
     * @param stealthAddress The expected stealth address.
     * @param ephemeralPubKey The ephemeral public key used to generate the stealth address.
     * @param viewingKey The recipient's viewing private key.
     * @param spendingKey The recipient's spending private key.
     * @return stealthKey The stealth private key corresponding to the stealth address.
     * @dev The stealth address input is not strictly necessary, but it is included so the method
     *      can validate that the stealth private key was generated correctly.
     */
    function computeStealthKey(
        address stealthAddress,
        bytes memory ephemeralPubKey,
        bytes memory viewingKey,
        bytes memory spendingKey
    ) internal view returns (bytes memory stealthKey) {
        // The `computeStealthKey` function performs the following computations:
        uint256 memPtr1 = Memory.allocate(64);
        uint256 memPtr2 = Memory.allocate(192);

        // forge-lint: disable-next-item(custom-errors)
        require(ephemeralPubKey.length == 33);

        uint8 ephemeralPubKeyCompressedY;
        uint256 ephemeralPubKeyX;
        uint256 ephemeralPubKeyY;

        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            ephemeralPubKeyCompressedY := byte(0, mload(add(ephemeralPubKey, 0x20)))
            ephemeralPubKeyX := mload(add(ephemeralPubKey, 0x21))
        }

        (, ephemeralPubKeyY) =
            Secp256k1Arithmetic.decompressToAffinePoint(memPtr2, ephemeralPubKeyX, ephemeralPubKeyCompressedY);

        // forge-lint: disable-next-item(custom-errors)
        require(viewingKey.length == 32);

        uint256 viewPrivKey;
        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            viewPrivKey := mload(add(viewingKey, 0x20))
        }
        // forge-lint: disable-next-item(custom-errors)
        require(Secp256k1.isValidNonZeroScalar(viewPrivKey));

        // forge-lint: disable-next-item(custom-errors)
        require(viewingKey.length == 32);

        uint256 spendPrivKey;
        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            spendPrivKey := mload(add(spendingKey, 0x20))
        }
        // forge-lint: disable-next-item(custom-errors)
        require(Secp256k1.isValidNonZeroScalar(spendPrivKey));

        // Shared secret $s$ is computed by multiplying the viewing private key with the ephemeral public key of the announcement $s = p_{view}$ * $P_{ephemeral}$.
        (uint256 sharedSecretX,) =
            Secp256k1Arithmetic.mulAffinePoint(memPtr1, ephemeralPubKeyX, ephemeralPubKeyY, viewPrivKey);

        // The secret is hashed $s_{h} = h(s)$.
        uint256 sharedSecretXHashed = Hashes.efficientKeccak256(sharedSecretX) % Secp256k1.N;
        // forge-lint: disable-next-item(custom-errors)
        require(sharedSecretXHashed != 0);

        // The stealth private key is computed as $p_{stealth} = p_{spend} + s_h$.
        uint256 stealthPrivKey = addmod(spendPrivKey, sharedSecretXHashed, Secp256k1.N);
        // forge-lint: disable-next-item(custom-errors)
        require(Secp256k1.isValidNonZeroScalar(stealthPrivKey));

        // https://github.com/verklegarden/crysol/pull/19
        uint256 e = 0;
        uint256 v = Secp256k1.yParityEthereum(Secp256k1.GY);
        uint256 r = Secp256k1.GX;
        uint256 s = mulmod(r, stealthPrivKey, Secp256k1.N);
        // casting to 'uint8' is safe because [explain why]
        // forge-lint: disable-next-item(unsafe-typecast)
        address recovered = address(uint160(ECDSA.recover(memPtr2, e, v, r, s)));
        // forge-lint: disable-next-item(custom-errors)
        require(recovered == stealthAddress);

        Memory.writeWord(memPtr1, 0x00, 32);
        Memory.writeWord(memPtr1, 0x20, stealthPrivKey);
        // forge-lint: disable-next-item(inline-assembly)
        assembly ("memory-safe") {
            /* reviewed: ... */
            stealthKey := memPtr1
        }
    }
}
