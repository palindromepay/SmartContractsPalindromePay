// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IPalindromeCryptoEscrow {
    enum State {
        AWAITING_PAYMENT,
        AWAITING_DELIVERY,
        DISPUTED,
        COMPLETE,
        REFUNDED,
        CANCELED
    }

    function getEscrow(uint256 escrowId)
        external
        view
        returns (
            address token,
            address buyer,
            address seller,
            address arbiter,
            address wallet,
            uint256 amount,
            uint256 depositTime,
            uint256 maturityTime,
            uint256 disputeStartTime,
            State state,
            bool buyerCancelRequested,
            bool sellerCancelRequested,
            uint8 tokenDecimals
        );
}

/// @title PalindromeEscrowWallet - Minimal 2-of-3 multisig wallet for escrow funds
/// @notice Holds funds for a single escrow, requires 2-of-3 signatures from buyer/seller/arbiter to move funds.
/// @dev Non-upgradeable, participant-controlled. Supports single split transfer (net + fee) via EIP-712 signatures.
contract PalindromeEscrowWallet is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // Escrow reference
    address public immutable escrowContract;
    uint256 public immutable escrowId;

    address public immutable buyer;
    address public immutable seller;
    address public immutable arbiter;
    address public immutable feeTo;
    uint256 public immutable netAmount;
    uint256 public immutable feeAmount;
    address public immutable token;

    uint8 public immutable threshold; // 2 for 2-of-3

    uint256 public nonce;

    // EIP-712
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant EXEC_SPLIT_TYPEHASH = keccak256(
        "ExecuteSplit(uint256 escrowId,address token,address to,address feeTo,uint256 nonce)"
    );
    bytes32 private immutable DOMAIN_SEPARATOR;

    event SplitExecuted(
        uint256 indexed nonce,
        address indexed token,
        address to,
        uint256 netAmount,
        address feeTo,
        uint256 feeAmount
    );

    constructor(
        address _escrowContract,
        uint256 _escrowId,
        address _token,
        address _buyer,
        address _seller,
        address _arbiter,
        address _feeTo,
        uint256 _netAmount,
        uint256 _feeAmount,
        uint8 _threshold
    ) {
        require(_escrowContract != address(0), "Escrow zero");
        require(
            _buyer != address(0) && _seller != address(0),
            "Zero address"
        );
        require(_threshold == 2, "Threshold must be 2");

        // Amount overflow + sanity checks
        uint256 total = _netAmount + _feeAmount;
        require(total >= _netAmount && total >= _feeAmount, "Amount overflow");

        escrowContract = _escrowContract;
        escrowId = _escrowId;

        token = _token;
        buyer = _buyer;
        seller = _seller;
        arbiter = _arbiter;
        feeTo = _feeTo;
        netAmount = _netAmount;
        feeAmount = _feeAmount;
        threshold = _threshold;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromeEscrowWallet")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Check if address is one of the owners
    function isOwner(address account) public view returns (bool) {
        return account == buyer || account == seller || account == arbiter;
    }

    /// @notice Execute a split ERC20 transfer (net + fee) with sufficient EIP-712 signatures
    /// @param to Recipient of the netAmount (fee goes to feeTo)
    /// @param signatures Array of signatures (65 bytes each, any order; empty bytes for non-signers)
   function executeERC20Split(
        address to,
        bytes[3] calldata signatures
    ) external nonReentrant {
        require(to != address(0), "Recipient zero");
        require(feeTo != address(0), "FeeTo zero");
        require(netAmount > 0 || feeAmount > 0, "Nothing to transfer");
        require(
            msg.sender == seller || msg.sender == buyer || msg.sender == arbiter,
            "executeERC20Split: Only participant"
        );

        // Check escrow state at coordinator
        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            IPalindromeCryptoEscrow.State state,
            ,
            ,

        ) = IPalindromeCryptoEscrow(escrowContract).getEscrow(escrowId);

        require(
            state == IPalindromeCryptoEscrow.State.COMPLETE ||
                state == IPalindromeCryptoEscrow.State.REFUNDED ||
                state == IPalindromeCryptoEscrow.State.CANCELED,
            "Escrow not payout-ready"
        );

        // Enforce correct beneficiary based on escrow state
        if (state == IPalindromeCryptoEscrow.State.COMPLETE) {
            require(to == seller, "Must pay seller on COMPLETE");
        } else if (
            state == IPalindromeCryptoEscrow.State.REFUNDED ||
            state == IPalindromeCryptoEscrow.State.CANCELED
        ) {
            require(to == buyer, "Must refund buyer on REFUNDED/CANCELED");
        }

        uint256 totalAmount = netAmount + feeAmount;
        require(totalAmount > netAmount && totalAmount > feeAmount, "Overflow");

        // Pre-transfer balances
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        require(balBefore >= totalAmount, "Insufficient wallet balance");

        uint256 toBefore = IERC20(token).balanceOf(to);
        uint256 feeBefore = IERC20(token).balanceOf(feeTo);

        // EIP-712 struct (now binds to escrowId)
        bytes32 structHash = keccak256(
            abi.encode(
                EXEC_SPLIT_TYPEHASH,
                escrowId,
                token,
                to,
                feeTo,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        uint8 sigCount = _countValidSignatures(digest, signatures);
        require(sigCount >= threshold, "Insufficient signatures");

        nonce++;

        // Transfers
        if (netAmount > 0) {
            IERC20(token).safeTransfer(to, netAmount);
        }
        if (feeAmount > 0) {
            IERC20(token).safeTransfer(feeTo, feeAmount);
        }

        // Post-transfer balances: enforce exact accounting
        uint256 toAfter = IERC20(token).balanceOf(to);
        uint256 feeAfter = IERC20(token).balanceOf(feeTo);
        uint256 balAfter = IERC20(token).balanceOf(address(this));

        if (netAmount > 0) {
            require(
                toAfter - toBefore == netAmount,
                "Net transfer mismatch"
            );
        }
        if (feeAmount > 0) {
            require(
                feeAfter - feeBefore == feeAmount,
                "Fee transfer mismatch"
            );
        }
        require(
            balBefore - balAfter == totalAmount,
            "Wallet balance mismatch"
        );

        emit SplitExecuted(nonce - 1, token, to, netAmount, feeTo, feeAmount);
    }

    /// @dev Internal helper to count and validate signatures (EIP-712 digest)
    function _countValidSignatures(
        bytes32 digest,
        bytes[3] calldata signatures
    ) internal view returns (uint8 count) {
        address[3] memory owners = [buyer, seller, arbiter];
        bool[3] memory signed;

        for (uint8 i = 0; i < 3; i++) {
            bytes calldata sig = signatures[i];
            if (sig.length != 65) continue;
            (bytes32 r, bytes32 s, uint8 v) = _splitSignature(sig);

            // Enforce canonical s and valid v
            require(
                uint256(s)
                    <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
                "Invalid s"
            );
            require(v == 27 || v == 28, "Invalid v");

            address recovered = ECDSA.recover(digest, v, r, s);
            if (recovered == address(0)) continue;

            // Match against owners, prevent double-count
            for (uint8 j = 0; j < 3; j++) {
                if (recovered == owners[j] && !signed[j]) {
                    signed[j] = true;
                    count++;
                    break;
                }
            }
        }
    }

    /// @dev Split signature into r, s, v
    function _splitSignature(
        bytes calldata sig
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
    }

    function getOwners() external view returns (address[] memory) {
        address[] memory owners = new address[](3);
        owners[0] = buyer;
        owners[1] = seller;
        owners[2] = arbiter;
        return owners;
    }
}
