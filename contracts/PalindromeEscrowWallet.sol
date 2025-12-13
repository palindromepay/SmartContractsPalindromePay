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

    struct EscrowDeal {
        address token;
        address buyer;
        address seller;
        address arbiter;
        address wallet;
        uint256 amount;
        uint256 depositTime;
        uint256 maturityTime;
        uint256 disputeStartTime;
        State state;
        bool buyerCancelRequested;
        bool sellerCancelRequested;
        uint8 tokenDecimals;
    }

    function getEscrow(uint256 escrowId)
        external
        view
        returns (EscrowDeal memory);
}

/// @title PalindromeEscrowWallet - Minimal 2-of-3 multisig wallet for escrow funds
/// @notice Holds funds for a single escrow, requires 2-of-3 signatures from buyer/seller/arbiter to move funds.
/// @dev Non-upgradeable, participant-controlled. Supports single split transfer (net + fee) via EIP-712 signatures.
contract PalindromeEscrowWallet is ReentrancyGuard {
    using SafeERC20 for IERC20;

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

    error SignatureLengthInvalid();
    error SignatureSInvalid();
    error SignatureVInvalid();

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

    function _recoverOwner(bytes32 digest, bytes memory signature)
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) {
            revert SignatureLengthInvalid();
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (
            uint256(s)
                > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            revert SignatureSInvalid();
        }

        if (v != 27 && v != 28) {
            revert SignatureVInvalid();
        }
        return ECDSA.recover(digest, v, r, s);
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

        IPalindromeCryptoEscrow.EscrowDeal memory deal =
            IPalindromeCryptoEscrow(escrowContract).getEscrow(escrowId);

        IPalindromeCryptoEscrow.State state = deal.state;

        require(
            state == IPalindromeCryptoEscrow.State.COMPLETE ||
                state == IPalindromeCryptoEscrow.State.REFUNDED ||
                state == IPalindromeCryptoEscrow.State.CANCELED,
            "Invalid escrow state"
        );

        if (state == IPalindromeCryptoEscrow.State.COMPLETE) {
            require(to == seller, "Must pay seller on COMPLETE");
        } else if (
            state == IPalindromeCryptoEscrow.State.REFUNDED ||
            state == IPalindromeCryptoEscrow.State.CANCELED
        ) {
            require(to == buyer, "Must refund buyer on REFUNDED/CANCELED");
        }

        // Build EIP-712 digest (unchanged)
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

        uint256 sigCount = _countValidSignatures(digest, signatures);
        require(sigCount >= threshold, "Not enough valid signatures");
        nonce += 1;

        IERC20 erc20 = IERC20(token);

        uint256 balanceBefore = erc20.balanceOf(address(this));

        uint256 fullAmount = netAmount + feeAmount;
        if (state == IPalindromeCryptoEscrow.State.COMPLETE) {
            if (netAmount > 0) {
                erc20.safeTransfer(to, netAmount);
            }
            if (feeAmount > 0) {
                erc20.safeTransfer(feeTo, feeAmount);
            }
        } else {
            erc20.safeTransfer(to, fullAmount);
        }

        uint256 balanceAfter = erc20.balanceOf(address(this));
        require(
            balanceAfter + fullAmount == balanceBefore,
            "Invariant: wrong transferred amount"
        );

        emit SplitExecuted(
            nonce - 1,
            token,
            to,
            netAmount,
            feeTo,
            feeAmount
        );
    }

    /// @dev Internal helper to count and validate signatures (EIP-712 digest)
    function _countValidSignatures(
        bytes32 digest,
        bytes[3] calldata signatures
    ) internal view returns (uint256 count) {
        bool seenBuyer;
        bool seenSeller;
        bool seenArbiter;

        for (uint256 i = 0; i < 3; i++) {
            bytes memory sig = signatures[i];
            if (sig.length == 0) {
                continue;
            }

            address signer = _recoverOwner(digest, sig);
            if (!isOwner(signer)) {
                continue;
            }

            if (signer == buyer && !seenBuyer) {
                seenBuyer = true;
                count++;
            } else if (signer == seller && !seenSeller) {
                seenSeller = true;
                count++;
            } else if (signer == arbiter && !seenArbiter) {
                seenArbiter = true;
                count++;
            }
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