// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IPalindromePay {
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
        uint256 maturityDuration;
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

    function FEE_RECEIVER() external view returns (address);
}

/**
 * @title PalindromePayWallet
 * @author Palindrome Pay
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
contract PalindromePayWallet is ReentrancyGuard {
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

    /// @dev The message participants sign to authorize a specific payout outcome.
    ///      `outcome` is the terminal State (COMPLETE=3, REFUNDED=4, CANCELED=5)
    ///      the signer consents to. A signature for one outcome can never satisfy
    ///      a withdrawal that resolves to a different outcome.
    bytes32 private constant PAYOUT_AUTHORIZATION_TYPEHASH = keccak256(
        "PayoutAuthorization(uint256 escrowId,address wallet,address escrowContract,address participant,uint8 outcome)"
    );

    // ---------------------------------------------------------------------
    // Immutables
    // ---------------------------------------------------------------------

    /// @notice The escrow contract that controls this wallet
    address public immutable ESCROW_CONTRACT;

    /// @notice The escrow ID this wallet belongs to
    uint256 public immutable ESCROW_ID;

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

    /// @notice Thrown when funds have already been withdrawn
    error AlreadyWithdrawn();

    /// @notice Thrown when escrow is not in a final state (COMPLETE, REFUNDED, CANCELED)
    error InvalidEscrowState();

    /// @notice Thrown when caller is not a participant
    error OnlyParticipant();

    /// @notice Thrown when token address is zero
    error TokenAddressZero();

    /// @notice Thrown when fee receiver address is zero
    error FeeReceiverZero();

    /// @notice Thrown when wallet is not empty after withdrawal
    error WalletNotEmpty();

    /// @notice Thrown when fewer than 2 valid signatures are present
    error InsufficientSignatures();

    /// @notice Thrown when a signature is invalid
    error InvalidSignature();

    /// @notice Thrown when signature length is not 65 bytes
    error SignatureLengthInvalid();

    /// @notice Thrown when signature 's' value is in upper half of curve
    error SignatureSInvalid();

    /// @notice Thrown when signature 'v' value is not 27 or 28
    error SignatureVInvalid();

    /// @notice Thrown when wallet address doesn't match deal.wallet
    error WalletMismatch();

    /// @notice Thrown when escrow contract address is zero
    error EscrowContractZero();

    /// @notice Thrown when amount is too small to cover the fee
    error AmountTooSmallForFee();

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
        if (_escrowContract == address(0)) revert EscrowContractZero();
        ESCROW_CONTRACT = _escrowContract;
        ESCROW_ID = _escrowId;

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
                keccak256(bytes("PalindromePayWallet")),
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
     * @dev Computes the EIP-712 digest for a participant's authorization of a
     *      specific payout outcome.
     * @param participant The participant's address
     * @param outcome The terminal State (COMPLETE/REFUNDED/CANCELED) authorized
     * @return The digest to sign
     */
    function _computeDigest(address participant, uint8 outcome) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                PAYOUT_AUTHORIZATION_TYPEHASH,
                ESCROW_ID,
                address(this),
                ESCROW_CONTRACT,
                participant,
                outcome
            )
        );

        return keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );
    }

    /**
     * @dev Validates and verifies a signature against expected signer for a
     *      specific outcome. A signature only counts for the exact outcome it
     *      was produced for.
     * @param signature The 65-byte signature
     * @param expectedSigner The address that should have signed
     * @param outcome The outcome the signature must authorize
     * @return True if signature is valid and matches expected signer + outcome
     */
    function _isValidSignature(
        bytes memory signature,
        address expectedSigner,
        uint8 outcome
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

        bytes32 digest = _computeDigest(expectedSigner, outcome);
        address recovered = ECDSA.recover(digest, v, r, s);

        return recovered == expectedSigner;
    }

    /**
     * @dev Evaluates whether the 2-of-3 (or authoritative single-signer)
     *      authorization is satisfied for a given terminal outcome.
     * @param deal The escrow deal struct
     * @param outcome The terminal State the withdrawal resolves to
     * @param beneficiary The address that receives funds for this outcome
     * @return authorized True if the withdrawal is authorized
     */
    function _isAuthorized(
        IPalindromePay.EscrowDeal memory deal,
        uint8 outcome,
        address beneficiary
    ) internal view returns (bool authorized) {
        bool bValid = _isValidSignature(deal.buyerWalletSig, deal.buyer, outcome);
        bool sValid = _isValidSignature(deal.sellerWalletSig, deal.seller, outcome);
        bool aValid = _isValidSignature(deal.arbiterWalletSig, deal.arbiter, outcome);

        uint256 count = 0;
        if (bValid) count++;
        if (sValid) count++;
        if (aValid) count++;

        // Cooperative / arbiter-plus-party path: any 2 of 3 authorize the outcome.
        if (count >= 2) return true;

        // Authoritative single-signer path (covers the unilateral timeout flows):
        //   - the arbiter alone (dispute tie-breaker), or
        //   - the sole beneficiary alone (autoRelease / cancelByTimeout / refund).
        // The escrow state machine independently gates whether the corresponding
        // terminal state could be reached, so a lone beneficiary signature can
        // never move funds without the on-chain timeout/authority condition.
        if (count == 1) {
            if (aValid) return true;
            if (bValid && beneficiary == deal.buyer) return true;
            if (sValid && beneficiary == deal.seller) return true;
        }

        return false;
    }

    // ---------------------------------------------------------------------
    // Fee Calculation
    // ---------------------------------------------------------------------

    /**
     * @dev Calculates fee and net amount (mirrors escrow contract logic)
     * @param amount Total amount to split
     * @param tokenDecimals Token decimal places for minimum fee calculation
     * @return netAmount Amount after fee deduction
     * @return feeAmount The 1% fee amount (minimum 0.01 tokens)
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
        if (feeAmount >= amount) revert AmountTooSmallForFee();
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

        IPalindromePay escrow = IPalindromePay(ESCROW_CONTRACT);
        IPalindromePay.EscrowDeal memory deal = escrow.getEscrow(ESCROW_ID);

        // Validate this wallet is the correct one for this escrow
        if (deal.wallet != address(this)) revert WalletMismatch();

        // Validate escrow is in final state
        IPalindromePay.State state = deal.state;
        if (
            state != IPalindromePay.State.COMPLETE &&
            state != IPalindromePay.State.REFUNDED &&
            state != IPalindromePay.State.CANCELED
        ) {
            revert InvalidEscrowState();
        }

        // Validate token address
        if (deal.token == address(0)) revert TokenAddressZero();

        // Only buyer or seller can trigger withdrawal
        if (
            msg.sender != deal.buyer &&
            msg.sender != deal.seller
        ) {
            revert OnlyParticipant();
        }

        // Determine beneficiary for this terminal outcome, then verify that the
        // participants authorized *this specific outcome* (not merely "some"
        // outcome). A COMPLETE authorization can no longer release a refund and
        // vice versa.
        address beneficiary =
            (state == IPalindromePay.State.COMPLETE) ? deal.seller : deal.buyer;
        if (!_isAuthorized(deal, uint8(state), beneficiary)) {
            revert InsufficientSignatures();
        }

        // Mark as withdrawn before external calls
        withdrawn = true;

        IERC20 token = IERC20(deal.token);
        uint256 balance = token.balanceOf(address(this));

        address recipient;
        uint256 netAmount;
        uint256 feeAmount;

        if (state == IPalindromePay.State.COMPLETE) {
            // Seller receives payment minus fee
            recipient = deal.seller;

            address feeTo = escrow.FEE_RECEIVER();
            if (feeTo == address(0)) revert FeeReceiverZero();

            (netAmount, feeAmount) = _computeFeeAndNet(balance, deal.tokenDecimals);

            // Transfer fee to fee receiver
            if (feeAmount > 0) {
                token.safeTransfer(feeTo, feeAmount);
            }

            // Transfer net amount to seller
            token.safeTransfer(recipient, netAmount);

            emit Withdrawn(ESCROW_ID, recipient, netAmount, feeTo, feeAmount);
        } else {
            // Buyer receives full refund (REFUNDED or CANCELED)
            recipient = deal.buyer;
            netAmount = balance;
            feeAmount = 0;

            token.safeTransfer(recipient, netAmount);

            emit Withdrawn(ESCROW_ID, recipient, netAmount, address(0), 0);
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
        IPalindromePay.EscrowDeal memory deal =
            IPalindromePay(ESCROW_CONTRACT).getEscrow(ESCROW_ID);

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
     * @notice Returns the digest a participant should sign to authorize a
     *         specific payout outcome
     * @param participant The participant's address
     * @param outcome The terminal State (COMPLETE=3, REFUNDED=4, CANCELED=5)
     * @return The EIP-712 digest to sign
     */
    function getAuthorizationDigest(address participant, uint8 outcome)
        external
        view
        returns (bytes32)
    {
        return _computeDigest(participant, outcome);
    }

    /**
     * @notice Returns the number of valid signatures stored for a given outcome
     * @param outcome The terminal State to check signatures against
     * @return count Number of valid signatures (0-3) authorizing that outcome
     */
    function getValidSignatureCount(uint8 outcome) external view returns (uint256 count) {
        IPalindromePay.EscrowDeal memory deal =
            IPalindromePay(ESCROW_CONTRACT).getEscrow(ESCROW_ID);
        if (_isValidSignature(deal.buyerWalletSig, deal.buyer, outcome)) count++;
        if (_isValidSignature(deal.sellerWalletSig, deal.seller, outcome)) count++;
        if (_isValidSignature(deal.arbiterWalletSig, deal.arbiter, outcome)) count++;
    }

    /**
     * @notice Checks if a participant's stored signature is valid for an outcome
     * @param participant The participant to check
     * @param outcome The terminal State to check against
     * @return True if the participant's signature authorizes that outcome
     */
    function isSignatureValid(address participant, uint8 outcome) external view returns (bool) {
        IPalindromePay.EscrowDeal memory deal =
            IPalindromePay(ESCROW_CONTRACT).getEscrow(ESCROW_ID);

        if (participant == deal.buyer) {
            return _isValidSignature(deal.buyerWalletSig, deal.buyer, outcome);
        } else if (participant == deal.seller) {
            return _isValidSignature(deal.sellerWalletSig, deal.seller, outcome);
        } else if (participant == deal.arbiter) {
            return _isValidSignature(deal.arbiterWalletSig, deal.arbiter, outcome);
        }
        return false;
    }
}
