// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import "./PalindromeEscrowWallet.sol";

/**
 * @title PalindromeCryptoEscrow
 * @notice Trustless escrow for ERC20 token transactions with dispute resolution
 * @dev Creates individual wallet contracts for each escrow using CREATE2.
 *      Supports buyer/seller cancellation, arbiter-based dispute resolution,
 *      and gasless operations via EIP-712 signatures.
 */
contract PalindromeCryptoEscrow is ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------------
    // Enums
    // ---------------------------------------------------------------------

    enum State {
        AWAITING_PAYMENT,
        AWAITING_DELIVERY,
        DISPUTED,
        COMPLETE,
        REFUNDED,
        CANCELED
    }

    enum Role {
        None,
        Buyer,
        Seller,
        Arbiter
    }

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    uint256 private constant _FEE_BPS = 100;
    uint256 private constant BPS_DENOMINATOR = 10_000;
    uint256 private constant MAX_STRING_LENGTH = 500;
    uint256 public constant DISPUTE_LONG_TIMEOUT = 30 days;
    uint256 public constant TIMEOUT_BUFFER = 1 hours;
    uint256 public constant GRACE_PERIOD = 24 hours;

    // ---------------------------------------------------------------------
    // Structs
    // ---------------------------------------------------------------------

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

    // ---------------------------------------------------------------------
    // Immutables
    // ---------------------------------------------------------------------

    address public immutable feeReceiver;
    bytes32 public immutable WALLET_BYTECODE_HASH;
    bytes32 private immutable INITIAL_DOMAIN_SEPARATOR;
    uint256 private immutable INITIAL_CHAIN_ID;

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------

    uint256 public nextEscrowId;

    mapping(uint256 => EscrowDeal) private escrows;
    mapping(bytes32 => bool) private usedSignatures;
    mapping(uint256 => bool) private arbiterDecisionSubmitted;
    mapping(uint256 => mapping(address => mapping(uint256 => uint256))) private nonceBitmap;
    mapping(uint256 => uint256) public disputeStatus;

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error InvalidNonce();
    error SignatureAlreadyUsed();
    error SignatureLengthInvalid();
    error SignatureSInvalid();
    error SignatureVInvalid();
    error OnlyBuyer();
    error OnlySeller();
    error OnlyArbiter();
    error OnlyBuyerOrSeller();
    error NotParticipant();

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event WalletCreated(uint256 indexed escrowId, address indexed wallet);

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

    event EscrowCreatedAndDeposited(
        uint256 indexed escrowId,
        address indexed buyer,
        uint256 amount
    );

    event PaymentDeposited(
        uint256 indexed escrowId,
        address indexed buyer,
        uint256 amount
    );

    event DeliveryConfirmed(
        uint256 indexed escrowId,
        address indexed buyer,
        address indexed seller,
        uint256 amount,
        uint256 fee
    );

    event RequestCancel(uint256 indexed escrowId, address indexed requester);

    event Canceled(
        uint256 indexed escrowId,
        address indexed initiator,
        uint256 amount
    );

    event DisputeStarted(uint256 indexed escrowId, address indexed initiator);

    event DisputeResolved(
        uint256 indexed escrowId,
        State resolution,
        address arbiter,
        uint256 amount,
        uint256 fee
    );

    event DisputeMessagePosted(
        uint256 indexed escrowId,
        address indexed sender,
        Role role,
        string ipfsHash
    );

    event DisputeDeadlinesSet(
        uint256 indexed escrowId,
        uint256 longDeadline
    );

    event PayoutProposed(
        uint256 indexed escrowId,
        address recipient,
        uint256 netAmount,
        address feeRecipient,
        uint256 feeAmount
    );

    event SellerWalletSigAttached(
        uint256 indexed escrowId,
        bytes sellerSig
    );

    event BuyerWalletSigAttached(
        uint256 indexed escrowId,
        bytes buyerSig
    );

    event ArbiterWalletSigAttached(
        uint256 indexed escrowId,
        bytes arbiterSig
    );

    event SellerAccepted(
        uint256 indexed escrowId,
        address indexed seller
    );

    event StateChanged(
        uint256 indexed escrowId,
        State oldState,
        State indexed newState
    );

    event AutoReleased(
        uint256 indexed escrowId,
        address indexed seller,
        uint256 amount,
        uint256 fee
    );

    // ---------------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------------

    modifier escrowExists(uint256 escrowId) {
        require(escrowId < nextEscrowId, "Escrow does not exist");
        require(escrows[escrowId].buyer != address(0), "Not initialized");
        _;
    }

    modifier onlyParticipant(uint256 escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        if (
            msg.sender != deal.buyer &&
            msg.sender != deal.seller &&
            msg.sender != deal.arbiter
        ) revert NotParticipant();
        _;
    }

    modifier onlyBuyerOrSeller(uint256 escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        if (msg.sender != deal.buyer && msg.sender != deal.seller) {
            revert OnlyBuyerOrSeller();
        }
        _;
    }

    modifier onlyBuyer(uint256 escrowId) {
        if (msg.sender != escrows[escrowId].buyer) revert OnlyBuyer();
        _;
    }

    modifier onlySeller(uint256 escrowId) {
        if (msg.sender != escrows[escrowId].seller) revert OnlySeller();
        _;
    }

    modifier onlyArbiter(uint256 escrowId) {
        if (msg.sender != escrows[escrowId].arbiter) revert OnlyArbiter();
        _;
    }

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    constructor(address _feeReceiver) {
        require(_feeReceiver != address(0), "FeeTo zero");
        feeReceiver = _feeReceiver;

        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _computeDomainSeparator();

        WALLET_BYTECODE_HASH = keccak256(
            type(PalindromeEscrowWallet).creationCode
        );
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getEscrow(uint256 escrowId)
        external
        view
        escrowExists(escrowId)
        returns (EscrowDeal memory)
    {
        return escrows[escrowId];
    }

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

    // ---------------------------------------------------------------------
    // Validation helpers
    // ---------------------------------------------------------------------

    function _validateIpfsLength(string calldata ipfsHash) internal pure {
        uint256 len = bytes(ipfsHash).length;
        require(len <= MAX_STRING_LENGTH, "Invalid IPFS hash length");
    }

    function _validateTitleLength(string calldata title) internal pure {
        uint256 len = bytes(title).length;
        require(len > 0 && len <= MAX_STRING_LENGTH, "Invalid title length");
    }

    // ---------------------------------------------------------------------
    // Coordinator EIP-712 domain (for *Signed functions)
    // ---------------------------------------------------------------------

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant CONFIRM_DELIVERY_TYPEHASH = keccak256(
        "ConfirmDelivery(uint256 escrowId,address buyer,address seller,address arbiter,address token,uint256 amount,uint256 depositTime,uint256 deadline,uint256 nonce)"
    );

    bytes32 private constant START_DISPUTE_TYPEHASH = keccak256(
        "StartDispute(uint256 escrowId,address buyer,address seller,address arbiter,address token,uint256 amount,uint256 depositTime,uint256 deadline,uint256 nonce)"
    );

    function _domainSeparator() internal view returns (bytes32) {
        if (block.chainid == INITIAL_CHAIN_ID) {
            return INITIAL_DOMAIN_SEPARATOR;
        } else {
            return _computeDomainSeparator();
        }
    }

    function _computeDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromeCryptoEscrow")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // ---------------------------------------------------------------------
    // Fee helpers
    // ---------------------------------------------------------------------

    function _calculateMinimumAmount(uint8 decimals)
        internal
        pure
        returns (uint256)
    {
        return 10 * (10 ** decimals);
    }

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

    function _setState(uint256 escrowId, State newState) internal {
        EscrowDeal storage deal = escrows[escrowId];
        State oldState = deal.state;
        deal.state = newState;
        emit StateChanged(escrowId, oldState, newState);
    }

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
            feeReceiver,
            feeTaken
        );
    }

    // ---------------------------------------------------------------------
    // Internal CREATE2 deploy
    // ---------------------------------------------------------------------

    function _deployWalletWithCreate2(uint256 escrowId)
        internal
        returns (address walletAddr)
    {
        bytes32 salt = keccak256(abi.encodePacked(escrowId));

        bytes memory bytecode = abi.encodePacked(
            type(PalindromeEscrowWallet).creationCode,
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

        require(sellerWalletSig.length == 65, "Missing seller sig");
        _validateSignatureFormat(sellerWalletSig);

        uint8 decimals = getTokenDecimals(token);
        uint256 minimumAmount = _calculateMinimumAmount(decimals);
        require(amount >= minimumAmount, "Amount too small");

        require(arbiter != msg.sender && arbiter != buyer, "Invalid arbiter");

        uint256 escrowId = nextEscrowId++;

        address walletAddr = _deployWalletWithCreate2(escrowId);

        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = buyer;
        deal.seller = msg.sender;
        deal.arbiter = arbiter;
        deal.wallet = walletAddr;
        deal.amount = amount;
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days);
        deal.state = State.AWAITING_PAYMENT;
        deal.tokenDecimals = decimals;

        deal.sellerWalletSig = sellerWalletSig;
        emit SellerWalletSigAttached(escrowId, sellerWalletSig);

        emit WalletCreated(escrowId, walletAddr);
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

        require(buyerWalletSig.length == 65, "Missing buyer sig");
        _validateSignatureFormat(buyerWalletSig);

        uint8 decimals = getTokenDecimals(token);
        uint256 minimumAmount = _calculateMinimumAmount(decimals);
        require(amount >= minimumAmount, "Amount too small");

        require(arbiter != msg.sender && arbiter != seller, "Invalid arbiter");

        escrowId = nextEscrowId++;

        address walletAddr = _deployWalletWithCreate2(escrowId);

        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = msg.sender;
        deal.seller = seller;
        deal.arbiter = arbiter;
        deal.wallet = walletAddr;
        deal.amount = amount;
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days);
        deal.state = State.AWAITING_PAYMENT;
        deal.tokenDecimals = decimals;

        deal.buyerWalletSig = buyerWalletSig;
        emit BuyerWalletSigAttached(escrowId, buyerWalletSig);

        emit WalletCreated(escrowId, walletAddr);
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

        require(buyerWalletSig.length == 65, "Missing buyer sig");
        _validateSignatureFormat(buyerWalletSig);
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
    // Seller Acceptance (for buyer-created escrows)
    // ---------------------------------------------------------------------

    /**
     * @notice Seller accepts a buyer-created escrow and provides wallet signature
     * @dev Required when buyer uses createEscrowAndDeposit so seller can authorize withdrawals
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
        require(deal.sellerWalletSig.length == 0, "Already accepted");

        require(sellerWalletSig.length == 65, "Missing seller sig");
        _validateSignatureFormat(sellerWalletSig);
        deal.sellerWalletSig = sellerWalletSig;

        emit SellerAccepted(escrowId, msg.sender);
        emit SellerWalletSigAttached(escrowId, sellerWalletSig);
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

        require(buyerWalletSig.length == 65, "Missing buyer sig");
        _validateSignatureFormat(buyerWalletSig);
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

        require(walletSig.length == 65, "Missing wallet sig");
        _validateSignatureFormat(walletSig);

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
     * @notice Cancels escrow after maturity time or grace period (called by buyer)
     * @dev If maturityTime is set, cancellation is allowed after maturityTime.
     *      If maturityTime is not set, cancellation is allowed after depositTime + GRACE_PERIOD.
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

        // If maturityTime is set, use it directly; otherwise use depositTime + GRACE_PERIOD
        if (deal.maturityTime != 0) {
            require(block.timestamp > deal.maturityTime, "Maturity not reached");
        } else {
            require(block.timestamp > deal.depositTime + GRACE_PERIOD, "Grace period active");
        }

        require(deal.buyerWalletSig.length == 65, "Missing buyer sig");

        _setState(escrowId, State.CANCELED);

        _proposePayout(escrowId, deal.buyer, false);

        emit Canceled(escrowId, msg.sender, deal.amount);
    }

    /**
     * @notice Auto-releases funds to seller after maturity time or grace period if buyer hasn't confirmed
     * @dev Seller can claim funds if:
     *      - Escrow is in AWAITING_DELIVERY state
     *      - No dispute has been started
     *      - Buyer has not requested cancellation
     *      - If maturityTime is set: maturityTime has passed
     *      - If maturityTime is not set: depositTime + GRACE_PERIOD has passed
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

        // If maturityTime is set, use it directly; otherwise use depositTime + GRACE_PERIOD
        if (deal.maturityTime != 0) {
            require(block.timestamp > deal.maturityTime, "Maturity not reached");
        } else {
            require(block.timestamp > deal.depositTime + GRACE_PERIOD, "Grace period active");
        }

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

        require(arbiterWalletSig.length == 65, "Missing arbiter sig");
        _validateSignatureFormat(arbiterWalletSig);
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

        bytes32 WALLET_AUTHORIZATION_TYPEHASH = keccak256(
            "WalletAuthorization(uint256 escrowId,address wallet,address participant)"
        );

        bytes32 walletDomainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromeEscrowWallet")),
                keccak256(bytes("1")),
                block.chainid,
                deal.wallet
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                WALLET_AUTHORIZATION_TYPEHASH,
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
     */
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }
}
