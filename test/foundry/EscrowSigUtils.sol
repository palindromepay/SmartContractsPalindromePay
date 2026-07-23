// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/// @notice Shared EIP-712 helpers mirroring PalindromePayWallet's signature
///         scheme, so the handler can produce outcome-bound signatures and the
///         invariants can re-verify stored ones without touching state.
abstract contract EscrowSigUtils {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 internal constant PAYOUT_AUTHORIZATION_TYPEHASH = keccak256(
        "PayoutAuthorization(uint256 escrowId,address wallet,address escrowContract,address participant,uint8 outcome)"
    );

    uint256 internal constant SECP256K1_HALF_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @dev Digest a participant signs to authorize `outcome` on `wallet`.
    ///      Works pre-deployment too (wallet address is CREATE2-predictable).
    function _payoutDigest(
        uint256 escrowId,
        address wallet,
        address escrowContract,
        address participant,
        uint8 outcome
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                PAYOUT_AUTHORIZATION_TYPEHASH,
                escrowId,
                wallet,
                escrowContract,
                participant,
                outcome
            )
        );
        bytes32 domainSep = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromePayWallet")),
                keccak256(bytes("1")),
                block.chainid,
                wallet
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
    }

    /// @dev View-only replica of PalindromePayWallet._isValidSignature.
    function _sigIsValidFor(
        bytes memory sig,
        address signer,
        uint256 escrowId,
        address wallet,
        address escrowContract,
        uint8 outcome
    ) internal view returns (bool) {
        if (sig.length != 65 || signer == address(0)) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }

        if (uint256(s) > SECP256K1_HALF_ORDER) return false;
        if (v != 27 && v != 28) return false;

        address recovered = ecrecover(
            _payoutDigest(escrowId, wallet, escrowContract, signer, outcome),
            v,
            r,
            s
        );
        return recovered == signer;
    }
}
