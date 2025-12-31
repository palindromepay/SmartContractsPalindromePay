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
        bytes sellerWalletSig;
        bytes buyerWalletSig;
        bytes arbiterWalletSig;
    }

    function getEscrow(uint256 escrowId)
        external
        view
        returns (EscrowDeal memory);

    function feeReceiver() external view returns (address);
}

/**
 * @title PalindromeEscrowWallet
 * @author Palindrome
 * @notice 2-of-3 multisig wallet for escrow fund release
 * @dev Holds funds for a single escrow deal. Requires 2 of 3 participant
 *      signatures (buyer, seller, arbiter) to withdraw funds.
 *
 *      Signatures are collected by the escrow contract during the deal
 *      lifecycle and cryptographically verified here at withdrawal time.
 *
 *      The recipient and fee structure are determined by the escrow state:
 *      - COMPLETE: seller receives funds minus 1% fee
 *      - REFUNDED/CANCELED: buyer receives full refund (no fee)
 */
contract PalindromeEscrowWallet is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    /// @dev 1% fee (100 basis points)
    uint256 private constant FEE_BPS = 100;
    uint256 private constant BPS_DENOMINATOR = 10_000;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @dev The message participants sign to authorize wallet operations
    bytes32 private constant WALLET_AUTHORIZATION_TYPEHASH = keccak256(
        "WalletAuthorization(uint256 escrowId,address wallet,address participant)"
    );

    // ---------------------------------------------------------------------
    // Immutables
    // ---------------------------------------------------------------------

    /// @notice The escrow contract that controls this wallet
    address public immutable escrowContract;

    /// @notice The escrow ID this wallet belongs to
    uint256 public immutable escrowId;

    /// @dev Cached domain separator for gas optimization
    bytes32 private immutable INITIAL_DOMAIN_SEPARATOR;

    /// @dev Chain ID at deployment for domain separator validation
    uint256 private immutable INITIAL_CHAIN_ID;

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------

    /// @notice Whether funds have been withdrawn
    bool public withdrawn;

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error AlreadyWithdrawn();
    error InvalidEscrowState();
    error OnlyParticipant();
    error TokenAddressZero();
    error FeeReceiverZero();
    error WalletNotEmpty();
    error InsufficientSignatures();
    error InvalidSignature();
    error SignatureLengthInvalid();
    error SignatureSInvalid();
    error SignatureVInvalid();

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    /// @notice Emitted when funds are withdrawn from the wallet
    /// @param escrowId The escrow ID
    /// @param recipient The address receiving the funds
    /// @param netAmount Amount sent to recipient
    /// @param feeReceiver Address receiving the fee (address(0) if no fee)
    /// @param feeAmount Fee amount (0 for refunds)
    event Withdrawn(
        uint256 indexed escrowId,
        address indexed recipient,
        uint256 netAmount,
        address indexed feeReceiver,
        uint256 feeAmount
    );

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    /**
     * @notice Creates a new escrow wallet
     * @param _escrowContract The escrow contract address
     * @param _escrowId The escrow ID this wallet belongs to
     */
    constructor(address _escrowContract, uint256 _escrowId) {
        require(_escrowContract != address(0), "Escrow zero");
        escrowContract = _escrowContract;
        escrowId = _escrowId;

        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _computeDomainSeparator();
    }

    // ---------------------------------------------------------------------
    // Domain Separator (Chain-ID Aware)
    // ---------------------------------------------------------------------

    /**
     * @dev Returns the domain separator, recomputing if chain ID changed (fork)
     */
    function _domainSeparator() internal view returns (bytes32) {
        if (block.chainid == INITIAL_CHAIN_ID) {
            return INITIAL_DOMAIN_SEPARATOR;
        }
        return _computeDomainSeparator();
    }

    function _computeDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromeEscrowWallet")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // ---------------------------------------------------------------------
    // Signature Verification
    // ---------------------------------------------------------------------

    /**
     * @dev Computes the EIP-712 digest for a participant's authorization
     * @param participant The participant's address
     * @return The digest to sign
     */
    function _computeDigest(address participant) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                WALLET_AUTHORIZATION_TYPEHASH,
                escrowId,
                address(this),
                participant
            )
        );

        return keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );
    }

    /**
     * @dev Validates and verifies a signature against expected signer
     * @param signature The 65-byte signature
     * @param expectedSigner The address that should have signed
     * @return True if signature is valid and matches expected signer
     */
    function _isValidSignature(
        bytes memory signature,
        address expectedSigner
    ) internal view returns (bool) {
        if (signature.length != 65) return false;
        if (expectedSigner == address(0)) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // Check s is in lower half of curve order (EIP-2)
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) return false;

        // Check v is valid
        if (v != 27 && v != 28) return false;

        bytes32 digest = _computeDigest(expectedSigner);
        address recovered = ECDSA.recover(digest, v, r, s);

        return recovered == expectedSigner;
    }

    /**
     * @dev Counts valid signatures from the escrow deal
     * @param deal The escrow deal struct
     * @return count Number of valid signatures (0-3)
     */
    function _countValidSignatures(
        IPalindromeCryptoEscrow.EscrowDeal memory deal
    ) internal view returns (uint256 count) {
        if (_isValidSignature(deal.buyerWalletSig, deal.buyer)) {
            count++;
        }
        if (_isValidSignature(deal.sellerWalletSig, deal.seller)) {
            count++;
        }
        if (_isValidSignature(deal.arbiterWalletSig, deal.arbiter)) {
            count++;
        }
    }

    // ---------------------------------------------------------------------
    // Fee Calculation
    // ---------------------------------------------------------------------

    /**
     * @dev Calculates fee and net amount (mirrors escrow contract logic)
     * @param amount Total amount
     * @param tokenDecimals Token decimals
     * @return netAmount Amount after fee
     * @return feeAmount Fee amount
     */
    function _computeFeeAndNet(
        uint256 amount,
        uint8 tokenDecimals
    ) internal pure returns (uint256 netAmount, uint256 feeAmount) {
        // Minimum fee: 0.01 tokens (adjusted for decimals)
        uint256 minFee = 10 ** (tokenDecimals > 2 ? tokenDecimals - 2 : 0);

        // Calculate 1% fee
        uint256 calculatedFee = (amount * FEE_BPS) / BPS_DENOMINATOR;

        // Use higher of calculated fee or minimum fee
        feeAmount = calculatedFee >= minFee ? calculatedFee : minFee;
        require(feeAmount < amount, "Amount too small for fee");
        netAmount = amount - feeAmount;
    }

    // ---------------------------------------------------------------------
    // Withdraw (2-of-3 Multisig)
    // ---------------------------------------------------------------------

    /**
     * @notice Withdraws funds from the wallet
     * @dev Requires:
     *      - Escrow state is COMPLETE, REFUNDED, or CANCELED
     *      - At least 2 of 3 valid participant signatures
     *      - Called by a participant (buyer, seller, or arbiter)
     *
     *      For COMPLETE: seller receives amount minus 1% fee
     *      For REFUNDED/CANCELED: buyer receives full amount
     */
    function withdraw() external nonReentrant {
        if (withdrawn) revert AlreadyWithdrawn();

        IPalindromeCryptoEscrow escrow = IPalindromeCryptoEscrow(escrowContract);
        IPalindromeCryptoEscrow.EscrowDeal memory deal = escrow.getEscrow(escrowId);

        // Validate escrow is in final state
        IPalindromeCryptoEscrow.State state = deal.state;
        if (
            state != IPalindromeCryptoEscrow.State.COMPLETE &&
            state != IPalindromeCryptoEscrow.State.REFUNDED &&
            state != IPalindromeCryptoEscrow.State.CANCELED
        ) {
            revert InvalidEscrowState();
        }

        // Validate token address
        if (deal.token == address(0)) revert TokenAddressZero();

        // Only participants can trigger withdrawal
        if (
            msg.sender != deal.buyer &&
            msg.sender != deal.seller &&
            msg.sender != deal.arbiter
        ) {
            revert OnlyParticipant();
        }

        // Verify 2-of-3 signatures
        uint256 validSigs = _countValidSignatures(deal);
        if (validSigs < 2) revert InsufficientSignatures();

        // Mark as withdrawn before external calls
        withdrawn = true;

        IERC20 token = IERC20(deal.token);
        uint256 balance = token.balanceOf(address(this));

        address recipient;
        uint256 netAmount;
        uint256 feeAmount;

        if (state == IPalindromeCryptoEscrow.State.COMPLETE) {
            // Seller receives payment minus fee
            recipient = deal.seller;

            address feeTo = escrow.feeReceiver();
            if (feeTo == address(0)) revert FeeReceiverZero();

            (netAmount, feeAmount) = _computeFeeAndNet(balance, deal.tokenDecimals);

            // Transfer fee to fee receiver
            if (feeAmount > 0) {
                token.safeTransfer(feeTo, feeAmount);
            }

            // Transfer net amount to seller
            token.safeTransfer(recipient, netAmount);

            emit Withdrawn(escrowId, recipient, netAmount, feeTo, feeAmount);
        } else {
            // Buyer receives full refund (REFUNDED or CANCELED)
            recipient = deal.buyer;
            netAmount = balance;
            feeAmount = 0;

            token.safeTransfer(recipient, netAmount);

            emit Withdrawn(escrowId, recipient, netAmount, address(0), 0);
        }

        // Verify wallet is empty (safety check)
        if (token.balanceOf(address(this)) != 0) revert WalletNotEmpty();
    }

    // ---------------------------------------------------------------------
    // View Functions
    // ---------------------------------------------------------------------

    /**
     * @notice Returns the current token balance in the wallet
     * @return The token balance
     */
    function getBalance() external view returns (uint256) {
        IPalindromeCryptoEscrow.EscrowDeal memory deal =
            IPalindromeCryptoEscrow(escrowContract).getEscrow(escrowId);

        if (deal.token == address(0)) return 0;
        return IERC20(deal.token).balanceOf(address(this));
    }

    /**
     * @notice Returns the EIP-712 domain separator
     * @return The domain separator
     */
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /**
     * @notice Returns the digest a participant should sign
     * @param participant The participant's address
     * @return The EIP-712 digest to sign
     */
    function getAuthorizationDigest(address participant)
        external
        view
        returns (bytes32)
    {
        return _computeDigest(participant);
    }

    /**
     * @notice Returns the number of valid signatures currently stored
     * @return count Number of valid signatures (0-3)
     */
    function getValidSignatureCount() external view returns (uint256 count) {
        IPalindromeCryptoEscrow.EscrowDeal memory deal =
            IPalindromeCryptoEscrow(escrowContract).getEscrow(escrowId);
        return _countValidSignatures(deal);
    }

    /**
     * @notice Checks if a participant's stored signature is valid
     * @param participant The participant to check
     * @return True if the participant's signature is valid
     */
    function isSignatureValid(address participant) external view returns (bool) {
        IPalindromeCryptoEscrow.EscrowDeal memory deal =
            IPalindromeCryptoEscrow(escrowContract).getEscrow(escrowId);

        if (participant == deal.buyer) {
            return _isValidSignature(deal.buyerWalletSig, deal.buyer);
        } else if (participant == deal.seller) {
            return _isValidSignature(deal.sellerWalletSig, deal.seller);
        } else if (participant == deal.arbiter) {
            return _isValidSignature(deal.arbiterWalletSig, deal.arbiter);
        }
        return false;
    }
}
