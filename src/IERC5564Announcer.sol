// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.36;

/**
 * @notice Interface for calling the `ERC5564Announcer` contract, which emits an `Announcement`
 *         event to broadcast information about a transaction involving a stealth address. See
 *         [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) to learn more.
 */
interface IERC5564Announcer {
    /**
     * @notice Emitted when something is sent to a stealth address.
     * @param schemeId Identifier corresponding to the applied stealth address scheme, e.g. 1 for
     *        secp256k1, as specified in ERC-5564.
     * @param stealthAddress The computed stealth address for the recipient.
     * @param caller The caller of the `announce` function that emitted this event.
     * @param ephemeralPubKey Ephemeral public key used by the sender to derive the `stealthAddress`.
     * @param metadata Arbitrary data to emit with the event. The first byte MUST be the view tag.
     * @dev The remaining metadata can be used by the senders however they like. See
     *      [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) for recommendations on how to structure
     *      this metadata.
     */
    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );

    /**
     * @notice Called by integrators to emit an `Announcement` event.
     * @param schemeId Identifier corresponding to the applied stealth address scheme, e.g. 1 for
     *        secp256k1, as specified in ERC-5564.
     * @param stealthAddress The computed stealth address for the recipient.
     * @param ephemeralPubKey Ephemeral public key used by the sender.
     * @param metadata An arbitrary field MUST include the view tag in the first byte.
     *        Besides the view tag, the metadata can be used by the senders however they like,
     *        but the below guidelines are recommended:
     *        The first byte of the metadata MUST be the view tag.
     *        - When sending/interacting with the native token of the blockchain (cf. ETH), the metadata SHOULD be structured as follows:
     *            - Byte 1 MUST be the view tag, as specified above.
     *            - Bytes 2-5 are `0xeeeeeeee`
     *            - Bytes 6-25 are the address 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE.
     *            - Bytes 26-57 are the amount of ETH being sent.
     *        - When interacting with ERC-20/ERC-721/etc. tokens, the metadata SHOULD be structured as follows:
     *          - Byte 1 MUST be the view tag, as specified above.
     *          - Bytes 2-5 are a function identifier. When a function selector (e.g.
     *            the first (left, high-order in big-endian) four bytes of the Keccak-256
     *            hash of the signature of the function, like Solidity and Vyper use) is
     *            available, it MUST be used.
     *          - Bytes 6-25 are the token contract address.
     *          - Bytes 26-57 are the amount of tokens being sent/interacted with for fungible tokens, or
     *            the token ID for non-fungible tokens.
     */
    function announce(uint256 schemeId, address stealthAddress, bytes memory ephemeralPubKey, bytes memory metadata)
        external;
}
