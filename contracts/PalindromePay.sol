// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {PalindromePayWallet} from "./PalindromePayWallet.sol";

/**
 * @title PalindromePay
 * @author Palindrome Pay
 * @notice Trustless escrow for ERC20 token transactions with dispute resolution
 * @dev Creates individual wallet contracts for each escrow using CREATE2.
 *      Supports buyer/seller cancellation, arbiter-based dispute resolution,
 *      and gasless operations via EIP-712 signatures.
 */
contract PalindromePay is ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------------
    // Enums
    // ---------------------------------------------------------------------

    /// @notice Possible states of an escrow deal
    enum State {
        AWAITING_PAYMENT,   // Escrow created, waiting for buyer deposit
        AWAITING_DELIVERY,  // Funds deposited, waiting for delivery confirmation
        DISPUTED,           // Dispute raised, awaiting arbiter decision
        COMPLETE,           // Delivery confirmed, seller paid
        REFUNDED,           // Dispute resolved in buyer's favor
        CANCELED            // Mutual cancellation or timeout
    }

    /// @notice Participant roles in an escrow
    enum Role {
        None,
        Buyer,
        Seller,
        Arbiter
    }

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    /// @dev Platform fee in basis points (1% = 100 bps)
    uint256 private constant _FEE_BPS = 100;

    /// @dev Basis points denominator (100% = 10,000 bps)
    uint256 private constant BPS_DENOMINATOR = 10_000;

    /// @dev Maximum length for title and IPFS hash strings
    uint256 private constant MAX_STRING_LENGTH = 500;

    /// @notice Maximum time for arbiter to resolve dispute
    uint256 public constant DISPUTE_LONG_TIMEOUT = 30 days;

    /// @notice Buffer time after dispute timeout before auto-resolution
    uint256 public constant TIMEOUT_BUFFER = 1 hours;

    // ---------------------------------------------------------------------
    // Structs
    // ---------------------------------------------------------------------

    /// @notice Represents a single escrow deal
    /// @dev Stored in the escrows mapping, indexed by escrowId
    struct EscrowDeal {
        address token;              // ERC20 token being escrowed
        address buyer;              // Party paying for goods/services
        address seller;             // Party providing goods/services
        address arbiter;            // Neutral party for dispute resolution
        address wallet;             // CREATE2-deployed wallet holding funds
        uint256 amount;             // Token amount in escrow
        uint256 depositTime;        // Timestamp when buyer deposited
        uint256 maturityTime;       // Deadline for delivery
        uint256 disputeStartTime;   // Timestamp when dispute was raised
        State state;                // Current escrow state
        bool buyerCancelRequested;  // Buyer has requested cancellation
        bool sellerCancelRequested; // Seller has requested cancellation
        uint8 tokenDecimals;        // Token decimals (cached for fee calc)
        bytes sellerWalletSig;      // Seller's wallet authorization signature
        bytes buyerWalletSig;       // Buyer's wallet authorization signature
        bytes arbiterWalletSig;     // Arbiter's wallet authorization signature
    }

    // ---------------------------------------------------------------------
    // Immutables
    // ---------------------------------------------------------------------

    /// @notice Address receiving platform fees
    address public immutable FEE_RECEIVER;

    /// @notice Keccak256 hash of wallet contract bytecode for CREATE2
    bytes32 public immutable WALLET_BYTECODE_HASH;

    /// @dev Cached EIP-712 domain separator at deployment
    bytes32 private immutable INITIAL_DOMAIN_SEPARATOR;

    /// @dev Chain ID at deployment for domain separator validation
    uint256 private immutable INITIAL_CHAIN_ID;

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------

    /// @notice Counter for generating unique escrow IDs
    uint256 public nextEscrowId;

    /// @dev Mapping of escrow ID to deal details
    mapping(uint256 => EscrowDeal) private escrows;

    /// @dev Tracks used signatures to prevent replay attacks
    mapping(bytes32 => bool) private usedSignatures;

    /// @dev Tracks whether arbiter has submitted decision for an escrow
    mapping(uint256 => bool) private arbiterDecisionSubmitted;

    /// @dev Bitmap for tracking used nonces: escrowId => signer => bucket => bitmap
    mapping(uint256 => mapping(address => mapping(uint256 => uint256))) private nonceBitmap;

    /// @notice Bitmap tracking dispute evidence submission (bit 0 = buyer, bit 1 = seller)
    mapping(uint256 => uint256) public disputeStatus;

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    /// @notice Thrown when a nonce has already been used
    error InvalidNonce();

    /// @notice Thrown when a signature has already been used
    error SignatureAlreadyUsed();

    /// @notice Thrown when signature length is not 65 bytes
    error SignatureLengthInvalid();

    /// @notice Thrown when signature 's' value is in upper half of curve
    error SignatureSInvalid();

    /// @notice Thrown when signature 'v' value is not 27 or 28
    error SignatureVInvalid();

    /// @notice Thrown when a wallet authorization signature is invalid
    error InvalidWalletSignature();

    /// @notice Thrown when caller is not the buyer
    error OnlyBuyer();

    /// @notice Thrown when caller is not the seller
    error OnlySeller();

    /// @notice Thrown when caller is not the arbiter
    error OnlyArbiter();

    /// @notice Thrown when caller is neither buyer nor seller
    error OnlyBuyerOrSeller();

    /// @notice Thrown when caller is not a participant (buyer, seller, or arbiter)
    error NotParticipant();

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    /// @notice Emitted when a new escrow wallet is deployed
    /// @param escrowId The unique escrow identifier
    /// @param wallet The deployed wallet contract address
    event WalletCreated(uint256 indexed escrowId, address indexed wallet);

    /// @notice Emitted when a new escrow is created
    /// @param escrowId The unique escrow identifier
    /// @param buyer The buyer's address
    /// @param seller The seller's address
    /// @param token The ERC20 token address
    /// @param amount The escrow amount
    /// @param arbiter The arbiter's address
    /// @param maturityTime The delivery deadline timestamp
    /// @param title The escrow title
    /// @param ipfsHash IPFS hash containing deal details
    event EscrowCreated(
        uint256 indexed escrowId,
        address indexed buyer,
        address indexed seller,
        address token,
        uint256 amount,
        address arbiter,
        uint256 maturityTime,
        string title,
        string ipfsHash
    );

    /// @notice Emitted when escrow is created and funded in one transaction
    /// @param escrowId The unique escrow identifier
    /// @param buyer The buyer's address
    /// @param amount The deposited amount
    event EscrowCreatedAndDeposited(
        uint256 indexed escrowId,
        address indexed buyer,
        uint256 amount
    );

    /// @notice Emitted when buyer deposits funds into escrow
    /// @param escrowId The unique escrow identifier
    /// @param buyer The buyer's address
    /// @param amount The deposited amount
    event PaymentDeposited(
        uint256 indexed escrowId,
        address indexed buyer,
        uint256 amount
    );

    /// @notice Emitted when buyer confirms delivery
    /// @param escrowId The unique escrow identifier
    /// @param buyer The buyer's address
    /// @param seller The seller's address
    /// @param amount The total escrow amount
    /// @param fee The platform fee deducted
    event DeliveryConfirmed(
        uint256 indexed escrowId,
        address indexed buyer,
        address indexed seller,
        uint256 amount,
        uint256 fee
    );

    /// @notice Emitted when buyer or seller requests cancellation
    /// @param escrowId The unique escrow identifier
    /// @param requester The address requesting cancellation
    event RequestCancel(uint256 indexed escrowId, address indexed requester);

    /// @notice Emitted when escrow is canceled
    /// @param escrowId The unique escrow identifier
    /// @param initiator The address that triggered cancellation
    /// @param amount The refunded amount
    event Canceled(
        uint256 indexed escrowId,
        address indexed initiator,
        uint256 amount
    );

    /// @notice Emitted when a dispute is started
    /// @param escrowId The unique escrow identifier
    /// @param initiator The address that started the dispute
    event DisputeStarted(uint256 indexed escrowId, address indexed initiator);

    /// @notice Emitted when arbiter resolves a dispute
    /// @param escrowId The unique escrow identifier
    /// @param resolution The final state (COMPLETE or REFUNDED)
    /// @param arbiter The arbiter's address
    /// @param amount The total escrow amount
    /// @param fee The platform fee (0 for refunds)
    event DisputeResolved(
        uint256 indexed escrowId,
        State resolution,
        address arbiter,
        uint256 amount,
        uint256 fee
    );

    /// @notice Emitted when evidence is submitted during dispute
    /// @param escrowId The unique escrow identifier
    /// @param sender The address submitting evidence
    /// @param role The sender's role (Buyer, Seller, or Arbiter)
    /// @param ipfsHash IPFS hash of the evidence
    event DisputeMessagePosted(
        uint256 indexed escrowId,
        address indexed sender,
        Role role,
        string ipfsHash
    );

    /// @notice Emitted when dispute deadlines are set
    /// @param escrowId The unique escrow identifier
    /// @param longDeadline The long timeout deadline
    event DisputeDeadlinesSet(
        uint256 indexed escrowId,
        uint256 longDeadline
    );

    /// @notice Emitted when payout is proposed for wallet withdrawal
    /// @param escrowId The unique escrow identifier
    /// @param recipient The address to receive funds
    /// @param netAmount Amount after fees
    /// @param feeRecipient The fee receiver address
    /// @param feeAmount The fee amount
    event PayoutProposed(
        uint256 indexed escrowId,
        address recipient,
        uint256 netAmount,
        address feeRecipient,
        uint256 feeAmount
    );

    /// @notice Emitted when seller's wallet signature is stored
    /// @param escrowId The unique escrow identifier
    /// @param sellerSig The seller's signature
    event SellerWalletSigAttached(
        uint256 indexed escrowId,
        bytes sellerSig
    );

    /// @notice Emitted when buyer's wallet signature is stored
    /// @param escrowId The unique escrow identifier
    /// @param buyerSig The buyer's signature
    event BuyerWalletSigAttached(
        uint256 indexed escrowId,
        bytes buyerSig
    );

    /// @notice Emitted when arbiter's wallet signature is stored
    /// @param escrowId The unique escrow identifier
    /// @param arbiterSig The arbiter's signature
    event ArbiterWalletSigAttached(
        uint256 indexed escrowId,
        bytes arbiterSig
    );

    /// @notice Emitted when seller accepts a buyer-created escrow
    /// @param escrowId The unique escrow identifier
    /// @param seller The seller's address
    event SellerAccepted(
        uint256 indexed escrowId,
        address indexed seller
    );

    /// @notice Emitted when seller updates their wallet signature
    /// @param escrowId The unique escrow identifier
    /// @param sellerSig The new seller's signature
    event SellerWalletSigUpdated(
        uint256 indexed escrowId,
        bytes sellerSig
    );

    /// @notice Emitted when escrow state changes
    /// @param escrowId The unique escrow identifier
    /// @param oldState The previous state
    /// @param newState The new state
    event StateChanged(
        uint256 indexed escrowId,
        State oldState,
        State indexed newState
    );

    /// @notice Emitted when funds are auto-released to seller after timeout
    /// @param escrowId The unique escrow identifier
    /// @param seller The seller's address
    /// @param amount The total escrow amount
    /// @param fee The platform fee deducted
    event AutoReleased(
        uint256 indexed escrowId,
        address indexed seller,
        uint256 amount,
        uint256 fee
    );

    // ---------------------------------------------------------------------
    // Modifiers (with internal functions to reduce bytecode)
    // ---------------------------------------------------------------------

    /// @dev Internal function for escrowExists modifier
    function _escrowExists(uint256 escrowId) internal view {
        require(escrowId < nextEscrowId, "Escrow does not exist");
        require(escrows[escrowId].buyer != address(0), "Not initialized");
    }

    /// @notice Ensures the escrow exists and is initialized
    /// @param escrowId The escrow ID to check
    modifier escrowExists(uint256 escrowId) {
        _escrowExists(escrowId);
        _;
    }

    /// @dev Internal function for onlyParticipant modifier
    function _onlyParticipant(uint256 escrowId) internal view {
        EscrowDeal storage deal = escrows[escrowId];
        if (
            msg.sender != deal.buyer &&
            msg.sender != deal.seller &&
            msg.sender != deal.arbiter
        ) revert NotParticipant();
    }

    /// @notice Restricts access to escrow participants only
    /// @param escrowId The escrow ID
    modifier onlyParticipant(uint256 escrowId) {
        _onlyParticipant(escrowId);
        _;
    }

    /// @dev Internal function for onlyBuyerOrSeller modifier
    function _onlyBuyerOrSeller(uint256 escrowId) internal view {
        EscrowDeal storage deal = escrows[escrowId];
        if (msg.sender != deal.buyer && msg.sender != deal.seller) {
            revert OnlyBuyerOrSeller();
        }
    }

    /// @notice Restricts access to buyer or seller only
    /// @param escrowId The escrow ID
    modifier onlyBuyerOrSeller(uint256 escrowId) {
        _onlyBuyerOrSeller(escrowId);
        _;
    }

    /// @dev Internal function for onlyBuyer modifier
    function _onlyBuyer(uint256 escrowId) internal view {
        if (msg.sender != escrows[escrowId].buyer) revert OnlyBuyer();
    }

    /// @notice Restricts access to buyer only
    /// @param escrowId The escrow ID
    modifier onlyBuyer(uint256 escrowId) {
        _onlyBuyer(escrowId);
        _;
    }

    /// @dev Internal function for onlySeller modifier
    function _onlySeller(uint256 escrowId) internal view {
        if (msg.sender != escrows[escrowId].seller) revert OnlySeller();
    }

    /// @notice Restricts access to seller only
    /// @param escrowId The escrow ID
    modifier onlySeller(uint256 escrowId) {
        _onlySeller(escrowId);
        _;
    }

    /// @dev Internal function for onlyArbiter modifier
    function _onlyArbiter(uint256 escrowId) internal view {
        if (msg.sender != escrows[escrowId].arbiter) revert OnlyArbiter();
    }

    /// @notice Restricts access to arbiter only
    /// @param escrowId The escrow ID
    modifier onlyArbiter(uint256 escrowId) {
        _onlyArbiter(escrowId);
        _;
    }

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    /// @notice Initializes the escrow contract
    /// @param _feeReceiver Address to receive platform fees
    constructor(address _feeReceiver) {
        require(_feeReceiver != address(0), "FeeTo zero");
        FEE_RECEIVER = _feeReceiver;

        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _computeDomainSeparator();

        WALLET_BYTECODE_HASH = keccak256(
            type(PalindromePayWallet).creationCode
        );
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    /// @notice Retrieves escrow deal details
    /// @param escrowId The escrow ID
    /// @return The EscrowDeal struct containing all deal details
    function getEscrow(uint256 escrowId)
        external
        view
        escrowExists(escrowId)
        returns (EscrowDeal memory)
    {
        return escrows[escrowId];
    }

    /// @dev Retrieves and validates token decimals
    /// @param token The ERC20 token address
    /// @return The token's decimal places (must be 6-18)
    function getTokenDecimals(address token)
        internal
        view
        returns (uint8)
    {
        try IERC20Metadata(token).decimals{gas: 30000}() returns (uint8 dec) {
            require(dec >= 6 && dec <= 18, "Unsupported decimals");
            return dec;
        } catch {
            revert("Token must implement decimals()");
        }
    }

    // ---------------------------------------------------------------------
    // Internal nonce & signature guards (for *Signed coordinator calls)
    // ---------------------------------------------------------------------

    /// @dev Marks a nonce as used for replay protection
    /// @param escrowId The escrow ID
    /// @param signer The signer's address
    /// @param nonce The nonce to mark as used
    function _useNonce(
        uint256 escrowId,
        address signer,
        uint256 nonce
    ) internal {
        uint256 bucket = nonce / 256;
        uint256 bit = nonce % 256;

        uint256 bitmap = nonceBitmap[escrowId][signer][bucket];
        uint256 mask = 1 << bit;

        if (bitmap & mask != 0) revert InvalidNonce();

        nonceBitmap[escrowId][signer][bucket] = bitmap | mask;
    }

    /// @dev Validates and marks a coordinator signature as used
    /// @param escrowId The escrow ID
    /// @param signature The 65-byte signature to validate and consume
    function _useSignature(uint256 escrowId, bytes calldata signature)
        internal
    {
        if (signature.length != 65) revert SignatureLengthInvalid();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(add(signature.offset, 0))
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) revert SignatureSInvalid();

        if (v != 27 && v != 28) revert SignatureVInvalid();

        bytes32 canonicalSigHash = keccak256(
            abi.encodePacked(address(this), escrowId, r, s, block.chainid)
        );
        if (usedSignatures[canonicalSigHash]) revert SignatureAlreadyUsed();
        usedSignatures[canonicalSigHash] = true;
    }

    /// @dev Validates signature format without consuming it
    /// @param signature The 65-byte signature to validate
    function _validateSignatureFormat(bytes calldata signature)
        internal
        pure
    {
        if (signature.length != 65) revert SignatureLengthInvalid();
        bytes32 s;
        uint8 v;
        assembly {
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) revert SignatureSInvalid();
        if (v != 27 && v != 28) revert SignatureVInvalid();
    }

    /// @dev Verifies a wallet authorization signature
    /// @param signature The 65-byte signature
    /// @param escrowId The escrow ID
    /// @param walletAddr The wallet address (can be predicted)
    /// @param expectedSigner The address that should have signed
    /// @return True if signature is valid
    function _verifyWalletSignature(
        bytes calldata signature,
        uint256 escrowId,
        address walletAddr,
        address expectedSigner
    ) internal view returns (bool) {
        if (signature.length != 65) return false;
        if (expectedSigner == address(0)) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(add(signature.offset, 0))
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Check s is in lower half of curve order (EIP-2)
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }
        if (v != 27 && v != 28) return false;

        // Compute digest (same as PalindromePayWallet._computeDigest)
        bytes32 walletAuthorizationTypehash = keccak256(
            "WalletAuthorization(uint256 escrowId,address wallet,address participant)"
        );

        bytes32 walletDomainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromePayWallet")),
                keccak256(bytes("1")),
                block.chainid,
                walletAddr
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(walletAuthorizationTypehash, escrowId, walletAddr, expectedSigner)
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", walletDomainSeparator, structHash)
        );

        address recovered = ECDSA.recover(digest, v, r, s);
        return recovered == expectedSigner;
    }

    // ---------------------------------------------------------------------
    // Validation helpers
    // ---------------------------------------------------------------------

    /// @dev Validates IPFS hash length
    /// @param ipfsHash The IPFS hash to validate
    function _validateIpfsLength(string calldata ipfsHash) internal pure {
        uint256 len = bytes(ipfsHash).length;
        require(len <= MAX_STRING_LENGTH, "Invalid IPFS hash length");
    }

    /// @dev Validates title length (must be 1-500 characters)
    /// @param title The title to validate
    function _validateTitleLength(string calldata title) internal pure {
        uint256 len = bytes(title).length;
        require(len > 0 && len <= MAX_STRING_LENGTH, "Invalid title length");
    }

    // ---------------------------------------------------------------------
    // Coordinator EIP-712 domain (for *Signed functions)
    // ---------------------------------------------------------------------

    /// @dev EIP-712 domain type hash
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @dev Type hash for confirmDeliverySigned
    bytes32 private constant CONFIRM_DELIVERY_TYPEHASH = keccak256(
        "ConfirmDelivery(uint256 escrowId,address buyer,address seller,address arbiter,address token,uint256 amount,uint256 depositTime,uint256 deadline,uint256 nonce)"
    );

    /// @dev Type hash for startDisputeSigned
    bytes32 private constant START_DISPUTE_TYPEHASH = keccak256(
        "StartDispute(uint256 escrowId,address buyer,address seller,address arbiter,address token,uint256 amount,uint256 depositTime,uint256 deadline,uint256 nonce)"
    );

    /// @dev Returns domain separator, recomputing if chain ID changed (fork)
    /// @return The EIP-712 domain separator
    function _domainSeparator() internal view returns (bytes32) {
        if (block.chainid == INITIAL_CHAIN_ID) {
            return INITIAL_DOMAIN_SEPARATOR;
        } else {
            return _computeDomainSeparator();
        }
    }

    /// @dev Computes the EIP-712 domain separator
    /// @return The computed domain separator
    function _computeDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromePay")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // ---------------------------------------------------------------------
    // Fee helpers
    // ---------------------------------------------------------------------

    /// @dev Calculates minimum escrow amount based on token decimals
    /// @param decimals The token's decimal places
    /// @return Minimum amount (10 tokens in smallest unit)
    function _calculateMinimumAmount(uint8 decimals)
        internal
        pure
        returns (uint256)
    {
        return 10 * (10 ** decimals);
    }

    /// @dev Calculates fee and net amount for payouts
    /// @param amount The total amount
    /// @param tokenDecimals The token's decimal places
    /// @param applyFee Whether to apply the 1% fee
    /// @return netAmount Amount after fee deduction
    /// @return feeAmount The fee amount (0 if applyFee is false)
    function _computeFeeAndNet(
        uint256 amount,
        uint8 tokenDecimals,
        bool applyFee
    ) internal pure returns (uint256 netAmount, uint256 feeAmount) {
        uint256 minFee = 10 ** (tokenDecimals > 2 ? tokenDecimals - 2 : 0);

        if (applyFee) {
            uint256 calculatedFee = (amount * _FEE_BPS) / BPS_DENOMINATOR;
            feeAmount = calculatedFee >= minFee ? calculatedFee : minFee;
            require(feeAmount < amount, "Amount too small for fee");
            netAmount = amount - feeAmount;
        } else {
            feeAmount = 0;
            netAmount = amount;
        }
    }

    // ---------------------------------------------------------------------
    // State & payout helpers
    // ---------------------------------------------------------------------

    /// @dev Updates escrow state and emits StateChanged event
    /// @param escrowId The escrow ID
    /// @param newState The new state to set
    function _setState(uint256 escrowId, State newState) internal {
        EscrowDeal storage deal = escrows[escrowId];
        State oldState = deal.state;
        deal.state = newState;
        emit StateChanged(escrowId, oldState, newState);
    }

    /// @dev Calculates and emits payout proposal for wallet withdrawal
    /// @param escrowId The escrow ID
    /// @param recipient The address to receive funds
    /// @param applyFee Whether to apply the platform fee
    /// @return netAmount Amount recipient will receive
    /// @return feeTaken Fee amount (0 if applyFee is false)
    function _proposePayout(
        uint256 escrowId,
        address recipient,
        bool applyFee
    ) internal returns (uint256 netAmount, uint256 feeTaken) {
        EscrowDeal storage deal = escrows[escrowId];

        if (applyFee) {
            (netAmount, feeTaken) =
                _computeFeeAndNet(deal.amount, deal.tokenDecimals, true);
        } else {
            netAmount = deal.amount;
            feeTaken = 0;
        }

        emit PayoutProposed(
            escrowId,
            recipient,
            netAmount,
            FEE_RECEIVER,
            feeTaken
        );
    }

    // ---------------------------------------------------------------------
    // Internal CREATE2 deploy
    // ---------------------------------------------------------------------

    /// @dev Predicts wallet address for a given escrow ID (before deployment)
    /// @param escrowId The escrow ID used as salt
    /// @return predicted The predicted wallet contract address
    function _predictWalletAddress(uint256 escrowId) internal view returns (address predicted) {
        bytes32 salt = keccak256(abi.encodePacked(escrowId));
        bytes32 bytecodeHash = keccak256(
            abi.encodePacked(
                type(PalindromePayWallet).creationCode,
                abi.encode(address(this), escrowId)
            )
        );
        predicted = address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, bytecodeHash)
        ))));
    }

    /// @dev Deploys a new escrow wallet using CREATE2 for deterministic addresses
    /// @param escrowId The escrow ID used as salt
    /// @return walletAddr The deployed wallet contract address
    function _deployWalletWithCreate2(uint256 escrowId)
        internal
        returns (address walletAddr)
    {
        bytes32 salt = keccak256(abi.encodePacked(escrowId));

        bytes memory bytecode = abi.encodePacked(
            type(PalindromePayWallet).creationCode,
            abi.encode(address(this), escrowId)
        );

        assembly ("memory-safe") {
            let codePtr := add(bytecode, 0x20)
            let codeSize := mload(bytecode)

            walletAddr := create2(0, codePtr, codeSize, salt)
            if iszero(walletAddr) {
                revert(0, 0)
            }
        }
    }

    // ---------------------------------------------------------------------
    // Create flows
    // ---------------------------------------------------------------------

    /**
     * @notice Creates a new escrow (called by seller)
     * @param token ERC20 token address
     * @param buyer Buyer's address
     * @param amount Token amount
     * @param maturityTimeDays Days until maturity
     * @param arbiter Arbiter's address for dispute resolution
     * @param title Escrow title
     * @param ipfsHash IPFS hash for additional details
     * @param sellerWalletSig Seller's EIP-712 signature for wallet authorization
     * @return escrowId The created escrow's ID
     */
    function createEscrow(
        address token,
        address buyer,
        uint256 amount,
        uint256 maturityTimeDays,
        address arbiter,
        string calldata title,
        string calldata ipfsHash,
        bytes calldata sellerWalletSig
    ) external returns (uint256) {
        _validateTitleLength(title);
        _validateIpfsLength(ipfsHash);
        require(token != address(0), "Token zero");
        require(buyer != address(0), "Buyer zero");
        require(buyer != msg.sender, "Buyer seller same");
        require(amount > 0, "Amount zero");
        require(maturityTimeDays < 3651, "Maturity too long");

        uint8 decimals = getTokenDecimals(token);
        uint256 minimumAmount = _calculateMinimumAmount(decimals);
        require(amount >= minimumAmount, "Amount too small");

        require(arbiter != msg.sender && arbiter != buyer, "Invalid arbiter");

        uint256 escrowId = nextEscrowId++;
        address predictedWallet = _predictWalletAddress(escrowId);

        // Verify seller signature before deploying wallet
        if (!_verifyWalletSignature(sellerWalletSig, escrowId, predictedWallet, msg.sender)) {
            revert InvalidWalletSignature();
        }

        address walletAddr = _deployWalletWithCreate2(escrowId);

        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = buyer;
        deal.seller = msg.sender;
        deal.arbiter = arbiter;
        deal.wallet = walletAddr;
        deal.amount = amount;
        require(maturityTimeDays >= 1, "Min 1 day maturity");
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days);
        deal.state = State.AWAITING_PAYMENT;
        deal.tokenDecimals = decimals;

        deal.sellerWalletSig = sellerWalletSig;

        emit EscrowCreated(
            escrowId,
            buyer,
            msg.sender,
            token,
            amount,
            arbiter,
            deal.maturityTime,
            title,
            ipfsHash
        );
        emit WalletCreated(escrowId, walletAddr);
        emit SellerWalletSigAttached(escrowId, sellerWalletSig);

        return escrowId;
    }

    /**
     * @notice Creates escrow and deposits in one transaction (called by buyer)
     * @param token ERC20 token address
     * @param seller Seller's address
     * @param amount Token amount
     * @param maturityTimeDays Days until maturity
     * @param arbiter Arbiter's address for dispute resolution
     * @param title Escrow title
     * @param ipfsHash IPFS hash for additional details
     * @param buyerWalletSig Buyer's EIP-712 signature for wallet authorization
     * @return escrowId The created escrow's ID
     */
    function createEscrowAndDeposit(
        address token,
        address seller,
        uint256 amount,
        uint256 maturityTimeDays,
        address arbiter,
        string calldata title,
        string calldata ipfsHash,
        bytes calldata buyerWalletSig
    ) external nonReentrant returns (uint256 escrowId) {
        _validateTitleLength(title);
        _validateIpfsLength(ipfsHash);
        require(token != address(0), "Token zero");
        require(seller != address(0), "Seller zero");
        require(seller != msg.sender, "Buyer seller same");
        require(amount > 0, "Amount zero");
        require(maturityTimeDays < 3651, "Maturity too long");

        uint8 decimals = getTokenDecimals(token);
        uint256 minimumAmount = _calculateMinimumAmount(decimals);
        require(amount >= minimumAmount, "Amount too small");

        require(arbiter != msg.sender && arbiter != seller, "Invalid arbiter");

        escrowId = nextEscrowId++;
        address predictedWallet = _predictWalletAddress(escrowId);

        // Verify buyer signature before deploying wallet
        if (!_verifyWalletSignature(buyerWalletSig, escrowId, predictedWallet, msg.sender)) {
            revert InvalidWalletSignature();
        }

        address walletAddr = _deployWalletWithCreate2(escrowId);

        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = msg.sender;
        deal.seller = seller;
        deal.arbiter = arbiter;
        deal.wallet = walletAddr;
        deal.amount = amount;
        require(maturityTimeDays >= 1, "Min 1 day maturity");
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days);
        deal.state = State.AWAITING_PAYMENT;
        deal.tokenDecimals = decimals;

        deal.buyerWalletSig = buyerWalletSig;

        emit EscrowCreated(
            escrowId,
            msg.sender,
            seller,
            token,
            amount,
            arbiter,
            deal.maturityTime,
            title,
            ipfsHash
        );
        emit WalletCreated(escrowId, walletAddr);
        emit BuyerWalletSigAttached(escrowId, buyerWalletSig);

        IERC20(token).safeTransferFrom(msg.sender, walletAddr, amount);
        deal.depositTime = block.timestamp;
        _setState(escrowId, State.AWAITING_DELIVERY);

        emit EscrowCreatedAndDeposited(escrowId, msg.sender, amount);
    }

    // ---------------------------------------------------------------------
    // Deposit
    // ---------------------------------------------------------------------

    /**
     * @notice Deposits funds into an existing escrow (called by buyer)
     * @param escrowId The escrow ID
     * @param buyerWalletSig Buyer's EIP-712 signature for wallet authorization
     */
    function deposit(
        uint256 escrowId,
        bytes calldata buyerWalletSig
    ) external nonReentrant escrowExists(escrowId) onlyBuyer(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_PAYMENT, "Not awaiting payment");

        // Verify buyer signature (wallet already exists)
        if (!_verifyWalletSignature(buyerWalletSig, escrowId, deal.wallet, msg.sender)) {
            revert InvalidWalletSignature();
        }
        deal.buyerWalletSig = buyerWalletSig;
        emit BuyerWalletSigAttached(escrowId, buyerWalletSig);

        IERC20(deal.token).safeTransferFrom(
            msg.sender,
            deal.wallet,
            deal.amount
        );
        deal.depositTime = block.timestamp;
        _setState(escrowId, State.AWAITING_DELIVERY);

        emit PaymentDeposited(escrowId, msg.sender, deal.amount);
    }

    // ---------------------------------------------------------------------
    // Seller Acceptance (for buyer-created escrows only)
    // ---------------------------------------------------------------------

    /**
     * @notice Seller accepts a buyer-created escrow and provides wallet signature
     * @dev Only for createEscrowAndDeposit flow. Not needed for createEscrow flow
     *      since seller already provides signature at creation time.
     * @param escrowId The escrow ID
     * @param sellerWalletSig Seller's EIP-712 signature for wallet authorization
     */
    function acceptEscrow(
        uint256 escrowId,
        bytes calldata sellerWalletSig
    ) external nonReentrant escrowExists(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(msg.sender == deal.seller, "Only seller");
        require(deal.state == State.AWAITING_DELIVERY, "Wrong state");

        // Verify seller signature (wallet already exists)
        if (!_verifyWalletSignature(sellerWalletSig, escrowId, deal.wallet, msg.sender)) {
            revert InvalidWalletSignature();
        }

        bool isUpdate = deal.sellerWalletSig.length > 0;
        deal.sellerWalletSig = sellerWalletSig;

        if (isUpdate) {
            emit SellerWalletSigUpdated(escrowId, sellerWalletSig);
        } else {
            emit SellerAccepted(escrowId, msg.sender);
            emit SellerWalletSigAttached(escrowId, sellerWalletSig);
        }
    }

    // ---------------------------------------------------------------------
    // Delivery confirmation
    // ---------------------------------------------------------------------

    /**
     * @notice Confirms delivery and releases funds to seller (called by buyer)
     * @param escrowId The escrow ID
     * @param buyerWalletSig Buyer's EIP-712 signature for wallet authorization
     */
    function confirmDelivery(
        uint256 escrowId,
        bytes calldata buyerWalletSig
    )
        external
        nonReentrant
        escrowExists(escrowId)
        onlyBuyer(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];
        require(
            deal.state == State.AWAITING_DELIVERY,
            "Not awaiting delivery"
        );
        require(deal.sellerWalletSig.length == 65, "Missing seller sig");

        // Verify buyer signature (wallet already exists)
        if (!_verifyWalletSignature(buyerWalletSig, escrowId, deal.wallet, msg.sender)) {
            revert InvalidWalletSignature();
        }
        deal.buyerWalletSig = buyerWalletSig;
        emit BuyerWalletSigAttached(escrowId, buyerWalletSig);

        _setState(escrowId, State.COMPLETE);

        (, uint256 fee) = _proposePayout(escrowId, deal.seller, true);
        emit DeliveryConfirmed(
            escrowId,
            deal.buyer,
            deal.seller,
            deal.amount,
            fee
        );
    }

    // ---------------------------------------------------------------------
    // Cancel flows
    // ---------------------------------------------------------------------

    /**
     * @notice Requests cancellation (requires both parties for mutual cancel)
     * @param escrowId The escrow ID
     * @param walletSig Caller's EIP-712 signature for wallet authorization
     */
    function requestCancel(
        uint256 escrowId,
        bytes calldata walletSig
    )
        external
        nonReentrant
        escrowExists(escrowId)
        onlyBuyerOrSeller(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];

        require(deal.state == State.AWAITING_DELIVERY, "Wrong state");
        require(deal.depositTime != 0, "No deposit");
        require(deal.disputeStartTime == 0, "Dispute active");

        // Verify wallet signature (wallet already exists)
        if (!_verifyWalletSignature(walletSig, escrowId, deal.wallet, msg.sender)) {
            revert InvalidWalletSignature();
        }

        bool isBuyer = (msg.sender == deal.buyer);

        // Store signature and validate not already requested
        if (isBuyer) {
            require(!deal.buyerCancelRequested, "Buyer already requested");
            deal.buyerWalletSig = walletSig;
            emit BuyerWalletSigAttached(escrowId, walletSig);
            deal.buyerCancelRequested = true;
        } else {
            require(!deal.sellerCancelRequested, "Seller already requested");
            deal.sellerWalletSig = walletSig;
            emit SellerWalletSigAttached(escrowId, walletSig);
            deal.sellerCancelRequested = true;
        }

        // Check if mutual cancel is complete
        if (deal.buyerCancelRequested && deal.sellerCancelRequested) {
            require(deal.buyerWalletSig.length == 65, "Missing buyer sig");
            require(deal.sellerWalletSig.length == 65, "Missing seller sig");

            _setState(escrowId, State.CANCELED);
            _proposePayout(escrowId, deal.buyer, false);

            emit Canceled(escrowId, msg.sender, deal.amount);
        } else {
            emit RequestCancel(escrowId, msg.sender);
        }
    }

    /**
     * @notice Cancels escrow after maturity time (called by buyer)
     * @dev Cancellation is allowed after maturityTime has passed.
     *      IMPORTANT: If no arbiter is set, timeout cancel is completely blocked.
     *      Without an arbiter, buyer must use mutual cancel (requestCancel) only.
     * @param escrowId The escrow ID
     */
    function cancelByTimeout(uint256 escrowId)
        external
        nonReentrant
        escrowExists(escrowId)
        onlyBuyer(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];

        require(
            deal.state == State.AWAITING_DELIVERY,
            "Not awaiting delivery"
        );
        require(deal.disputeStartTime == 0, "Dispute active");
        require(deal.buyerCancelRequested, "Must request first");
        require(!deal.sellerCancelRequested, "Mutual cancel done");
        require(deal.depositTime != 0, "No deposit");

        // No arbiter → block timeout cancel completely (only mutual cancel allowed)
        require(deal.arbiter != address(0), "Arbiter required for timeout cancel");

        require(block.timestamp > deal.maturityTime, "Maturity not reached");

        require(deal.buyerWalletSig.length == 65, "Missing buyer sig");

        _setState(escrowId, State.CANCELED);

        _proposePayout(escrowId, deal.buyer, false);

        emit Canceled(escrowId, msg.sender, deal.amount);
    }

    /**
     * @notice Auto-releases funds to seller after maturity time if buyer hasn't confirmed
     * @dev Seller can claim funds if:
     *      - Escrow is in AWAITING_DELIVERY state
     *      - No dispute has been started
     *      - Buyer has not requested cancellation
     *      - maturityTime has passed
     *      - Seller has provided wallet signature
     * @param escrowId The escrow ID
     */
    function autoRelease(uint256 escrowId)
        external
        nonReentrant
        escrowExists(escrowId)
        onlySeller(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];

        require(
            deal.state == State.AWAITING_DELIVERY,
            "Not awaiting delivery"
        );
        require(deal.disputeStartTime == 0, "Dispute active");
        require(!deal.buyerCancelRequested, "Buyer requested cancel");
        require(deal.depositTime != 0, "No deposit");

        require(block.timestamp > deal.maturityTime, "Maturity not reached");

        require(deal.sellerWalletSig.length == 65, "Missing seller sig");

        _setState(escrowId, State.COMPLETE);

        (, uint256 fee) = _proposePayout(escrowId, deal.seller, true);

        emit AutoReleased(escrowId, deal.seller, deal.amount, fee);
    }

    // ---------------------------------------------------------------------
    // Dispute flows
    // ---------------------------------------------------------------------

    /**
     * @notice Starts a dispute (called by buyer or seller)
     * @param escrowId The escrow ID
     */
    function startDispute(uint256 escrowId)
        external
        nonReentrant
        escrowExists(escrowId)
        onlyBuyerOrSeller(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.arbiter != address(0), "Zero arbiter");
        require(
            deal.state == State.AWAITING_DELIVERY,
            "Not awaiting delivery"
        );

        _setState(escrowId, State.DISPUTED);

        deal.disputeStartTime = block.timestamp;
        uint256 longDeadline = deal.disputeStartTime + DISPUTE_LONG_TIMEOUT;

        emit DisputeDeadlinesSet(escrowId, longDeadline);
        emit DisputeStarted(escrowId, msg.sender);
    }

    /**
     * @notice Submits evidence for a dispute (called by buyer or seller)
     * @param escrowId The escrow ID
     * @param role The caller's role (Buyer or Seller)
     * @param ipfsHash IPFS hash of the evidence
     */
    function submitDisputeMessage(
        uint256 escrowId,
        Role role,
        string calldata ipfsHash
    )
        external
        nonReentrant
        escrowExists(escrowId)
        onlyParticipant(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Not disputed");

        _validateIpfsLength(ipfsHash);

        uint256 status = disputeStatus[escrowId];

        if (role == Role.Buyer) {
            require(msg.sender == deal.buyer, "Only buyer");
            require((status & 1) == 0, "Already submitted");
            status |= 1;
        } else if (role == Role.Seller) {
            require(msg.sender == deal.seller, "Only seller");
            require((status & 2) == 0, "Already submitted");
            status |= 2;
        } else {
            revert("Invalid role");
        }

        disputeStatus[escrowId] = status;

        emit DisputeMessagePosted(escrowId, msg.sender, role, ipfsHash);
    }

    /**
     * @notice Submits arbiter's decision for a dispute
     * @param escrowId The escrow ID
     * @param resolution The resolution (COMPLETE or REFUNDED)
     * @param ipfsHash IPFS hash of the decision explanation
     * @param arbiterWalletSig Arbiter's EIP-712 signature for wallet authorization
     */
    function submitArbiterDecision(
        uint256 escrowId,
        State resolution,
        string calldata ipfsHash,
        bytes calldata arbiterWalletSig
    )
        external
        nonReentrant
        escrowExists(escrowId)
        onlyArbiter(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Invalid state");
        require(
            resolution == State.COMPLETE || resolution == State.REFUNDED,
            "Invalid resolution"
        );

        uint256 status = disputeStatus[escrowId];

        bool fullEvidence = ((status & 1) != 0) && ((status & 2) != 0);
        bool longTimeout =
            block.timestamp >
            deal.disputeStartTime + DISPUTE_LONG_TIMEOUT + TIMEOUT_BUFFER;

        require(fullEvidence || longTimeout, "Need evidence or timeout");
        require(!arbiterDecisionSubmitted[escrowId], "Already decided");

        arbiterDecisionSubmitted[escrowId] = true;

        // Verify arbiter signature (wallet already exists)
        if (!_verifyWalletSignature(arbiterWalletSig, escrowId, deal.wallet, msg.sender)) {
            revert InvalidWalletSignature();
        }
        deal.arbiterWalletSig = arbiterWalletSig;
        emit ArbiterWalletSigAttached(escrowId, arbiterWalletSig);

        _setState(escrowId, resolution);

        emit DisputeMessagePosted(escrowId, msg.sender, Role.Arbiter, ipfsHash);

        bool applyFee = (resolution == State.COMPLETE);
        address target = applyFee ? deal.seller : deal.buyer;
        (, uint256 fee) = _proposePayout(escrowId, target, applyFee);

        emit DisputeResolved(escrowId, resolution, msg.sender, deal.amount, fee);
    }

    // ---------------------------------------------------------------------
    // Signed coordinator flows
    // ---------------------------------------------------------------------

    /**
     * @notice Confirms delivery via EIP-712 signature (gasless for buyer)
     * @param escrowId The escrow ID
     * @param coordSignature Coordinator's EIP-712 signature
     * @param deadline Signature deadline
     * @param nonce Buyer's nonce
     * @param buyerWalletSig Buyer's wallet authorization signature
     */
    function confirmDeliverySigned(
        uint256 escrowId,
        bytes calldata coordSignature,
        uint256 deadline,
        uint256 nonce,
        bytes calldata buyerWalletSig
    ) external nonReentrant escrowExists(escrowId) {
        require(
            deadline > block.timestamp &&
                deadline < block.timestamp + 1 days,
            "Invalid deadline"
        );
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Invalid state");

        require(coordSignature.length == 65, "Missing coord sig");
        _validateSignatureFormat(coordSignature);

        require(buyerWalletSig.length == 65, "Missing buyer sig");
        _validateSignatureFormat(buyerWalletSig);

        require(deal.sellerWalletSig.length == 65, "Missing seller sig");

        bytes32 structHash = keccak256(
            abi.encode(
                CONFIRM_DELIVERY_TYPEHASH,
                escrowId,
                deal.buyer,
                deal.seller,
                deal.arbiter,
                deal.token,
                deal.amount,
                deal.depositTime,
                deadline,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );

        address signer = ECDSA.recover(digest, coordSignature);
        require(signer != address(0), "Invalid recovery");
        require(signer == deal.buyer, "Unauthorized signer");

        _useSignature(escrowId, coordSignature);
        _useNonce(escrowId, deal.buyer, nonce);

        deal.buyerWalletSig = buyerWalletSig;
        emit BuyerWalletSigAttached(escrowId, buyerWalletSig);

        _setState(escrowId, State.COMPLETE);

        (, uint256 fee) = _proposePayout(escrowId, deal.seller, true);

        emit DeliveryConfirmed(
            escrowId,
            deal.buyer,
            deal.seller,
            deal.amount,
            fee
        );
    }

    /**
     * @notice Starts dispute via EIP-712 signature (gasless for buyer/seller)
     * @param escrowId The escrow ID
     * @param signature Caller's EIP-712 signature
     * @param deadline Signature deadline
     * @param nonce Caller's nonce
     */
    function startDisputeSigned(
        uint256 escrowId,
        bytes calldata signature,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant escrowExists(escrowId) {
        require(
            deadline > block.timestamp &&
                deadline < block.timestamp + 1 days,
            "Invalid deadline"
        );
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Invalid state");
        _validateSignatureFormat(signature);

        bytes32 structHash = keccak256(
            abi.encode(
                START_DISPUTE_TYPEHASH,
                escrowId,
                deal.buyer,
                deal.seller,
                deal.arbiter,
                deal.token,
                deal.amount,
                deal.depositTime,
                deadline,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );

        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "Invalid recovery");
        require(
            signer == deal.buyer || signer == deal.seller,
            "Unauthorized signer"
        );

        _useSignature(escrowId, signature);
        _useNonce(escrowId, signer, nonce);

        _setState(escrowId, State.DISPUTED);

        deal.disputeStartTime = block.timestamp;
        uint256 longDeadline = deal.disputeStartTime + DISPUTE_LONG_TIMEOUT;

        emit DisputeDeadlinesSet(escrowId, longDeadline);
        emit DisputeStarted(escrowId, signer);
    }

    // ---------------------------------------------------------------------
    // View helpers for frontend
    // ---------------------------------------------------------------------

    /**
    * @notice Get the nonce bitmap for a given escrow/signer/word
    * @param escrowId The escrow ID
    * @param signer The signer's address  
    * @param wordIndex The word index (nonce / 256)
    * @return The bitmap where each bit represents if nonce (wordIndex*256 + bitPosition) is used
    */
    function getNonceBitmap(uint256 escrowId, address signer, uint256 wordIndex) external view returns (uint256) {
        return nonceBitmap[escrowId][signer][wordIndex];
    }

    /**
     * @notice Computes the wallet authorization digest for a participant
     * @dev Frontend can use this to generate the correct signature
     * @param escrowId The escrow ID
     * @param participant The participant's address
     * @return digest The EIP-712 digest to sign
     */
    function getWalletAuthorizationDigest(uint256 escrowId, address participant)
        external
        view
        escrowExists(escrowId)
        returns (bytes32 digest)
    {
        EscrowDeal storage deal = escrows[escrowId];
        require(
            participant == deal.buyer ||
            participant == deal.seller ||
            participant == deal.arbiter,
            "Not a participant"
        );

        bytes32 walletAuthorizationTypehash = keccak256(
            "WalletAuthorization(uint256 escrowId,address wallet,address participant)"
        );

        bytes32 walletDomainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromePayWallet")),
                keccak256(bytes("1")),
                block.chainid,
                deal.wallet
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                walletAuthorizationTypehash,
                escrowId,
                deal.wallet,
                participant
            )
        );

        digest = keccak256(
            abi.encodePacked("\x19\x01", walletDomainSeparator, structHash)
        );
    }

    /**
     * @notice Returns the escrow contract's domain separator
     * @return The EIP-712 domain separator
     */
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }
}
