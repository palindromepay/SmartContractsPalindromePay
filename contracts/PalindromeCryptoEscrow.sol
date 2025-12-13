// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "./PalindromeEscrowWallet.sol";

/// @title PalindromeCryptoEscrow - Non-custodial escrow coordinator with custom multisig wallet
/// @notice Coordinates escrow logic, disputes, and proposals, but does not control or move funds. Funds are held in participant-controlled 2-of-3 multisig wallets.
/// @dev Payouts are proposed via events for off-chain signature collection and execution on the wallet.
contract PalindromeCryptoEscrow is ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

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

    uint256 private constant _FEE_BPS = 100;
    uint256 private constant BPS_DENOMINATOR = 10_000;
    uint256 private constant MAX_STRING_LENGTH = 100;
    uint256 public constant DISPUTE_SHORT_TIMEOUT = 7 days;
    uint256 public constant DISPUTE_LONG_TIMEOUT = 30 days;
    uint256 public constant TIMEOUT_BUFFER = 1 hours;
    uint256 public constant GRACE_PERIOD = 24 hours;
    uint256 public constant EMERGENCY_RECOVERY_DELAY = 30 days;
    uint256 public constant MIN_EVIDENCE_WINDOW = 1 days; 
    uint256 public constant COMPLETE_RECOVERY_DELAY = 10 days; 

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

    struct DisputeEvidence {
        bool buyerSubmitted;
        bool sellerSubmitted;
        bool arbiterDecided;
    }

    uint256 public nextEscrowId;

    bytes32 private immutable INITIAL_DOMAIN_SEPARATOR;
    uint256 private immutable INITIAL_CHAIN_ID;

    mapping(uint256 => EscrowDeal) private escrows;
    mapping(uint256 => DisputeEvidence) private disputeEvidence;

    mapping(bytes32 => bool) private usedSignatures;
    mapping(uint256 => bool) private arbiterDecisionSubmitted;

    mapping(uint256 => uint256) public emergencyRecoveryInitiatedAt;
    mapping(uint256 => State)   public emergencyRecoveryStateAtInit;

    mapping(uint256 => mapping(address => mapping(uint256 => uint256))) private nonceBitmap;

    mapping(uint256 => uint256) public disputeStatus; 


    address public immutable feeReceiver;

    error InvalidMessageRoleForDispute();
    error InvalidNonce();
    error SignatureAlreadyUsed();
    error SignatureLengthInvalid();
    error SignatureSInvalid();
    error SignatureVInvalid();
    error OnlyBuyer();
    error OnlyArbiter();
    error OnlyBuyerOrSeller();
    error OnlySeller();
    error NotParticipant();

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
        uint256 fee, 
        string ipfsHaesh
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
    event PayoutProposed(
        uint256 indexed escrowId,
        address recipient,
        uint256 netAmount,
        address feeRecipient,
        uint256 feeAmount
    );
    event EscrowStateChanged(
        uint256 indexed escrowId,
        State oldState,
        State newState
    );
    event ArbiterReplaced(
        uint256 indexed escrowId,
        address indexed oldArbiter,
        address indexed newArbiter
    );
    event EmergencyRecoveryInitiated(
        uint256 indexed escrowId,
        uint256 timestamp
    );
    event EmergencyRecoveryExecuted(
        uint256 indexed escrowId,
        address indexed recipient,
        uint256 amount
    );

    event EmergencyRecoveryCancelled(uint256 indexed escrowId);

    event SellerWalletSigAttached(
        uint256 indexed escrowId, 
        bytes sellerSig
    );

    modifier escrowExists(uint256 escrowId) {
        require(escrowId < nextEscrowId, "Escrow does not exist");
        require(escrows[escrowId].buyer != address(0), "Escrow not initialized");
        _;
    }

    modifier onlyParticipant(uint256 escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        if (msg.sender != deal.buyer && msg.sender != deal.seller && msg.sender != deal.arbiter) {
            revert NotParticipant();
        }
        _;
    }

    modifier onlySeller(uint256 escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        if (msg.sender != deal.seller) {
            revert OnlySeller();
        }
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
        if (msg.sender != escrows[escrowId].buyer) {
            revert OnlyBuyer();
        }
        _;
    }

    modifier onlyArbiter(uint256 escrowId) {
        if (msg.sender != escrows[escrowId].arbiter) {
            revert OnlyArbiter();
        }
        _;
    }

    constructor(address _feeReceiver) {
        require(_feeReceiver != address(0), "FeeTo zero");
        feeReceiver = _feeReceiver;

        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _computeDomainSeparator();

    }

    function getNonceBitmap(
        uint256 escrowId,
        address signer,
        uint256 bucket
    ) external view returns (uint256) {
        return nonceBitmap[escrowId][signer][bucket];
    }

    function getEscrow(uint256 escrowId)
        external
        view
        escrowExists(escrowId)
        returns (EscrowDeal memory)
    {
        return escrows[escrowId];
    }

    function getTokenDecimals(address token) internal view returns (uint8) {
        try IERC20Metadata(token).decimals{gas: 30000}() returns (uint8 dec) {
            require(dec >= 6 && dec <= 18, "Unsupported decimals");
            return dec;
        } catch {
            revert("Token must implement decimals()");
        }
    }

    function _useNonce(uint256 escrowId, address signer, uint256 nonce) internal {
        uint256 bucket = nonce / 256;
        uint256 bit = nonce % 256;

        uint256 bitmap = nonceBitmap[escrowId][signer][bucket];
        uint256 mask = 1 << bit;

        if (bitmap & mask != 0) {
            revert InvalidNonce();
        }

        nonceBitmap[escrowId][signer][bucket] = bitmap | mask;
    }

    function isNonceUsed(uint256 escrowId, address signer, uint256 nonce)
        external
        view
        returns (bool) {
        uint256 bucket = nonce / 256;
        uint256 bit = nonce % 256;
        uint256 bitmap = nonceBitmap[escrowId][signer][bucket];
        uint256 mask = 1 << bit;
        return (bitmap & mask != 0);
    }

    function _useSignature(uint256 escrowId, bytes calldata signature) internal {
        if (signature.length != 65) {
            revert SignatureLengthInvalid();
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(add(signature.offset, 0))
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert SignatureSInvalid();
        }
        
        if (v != 27 && v != 28) {
            revert SignatureVInvalid();
        }

        bytes32 canonicalSigHash = keccak256(abi.encodePacked(  address(this), escrowId, r, s, block.chainid));
        if (usedSignatures[canonicalSigHash]) {
            revert SignatureAlreadyUsed();
        }
        usedSignatures[canonicalSigHash] = true;
    }

    function _validateIpfsLength(string calldata ipfsHash) internal pure {
        uint256 len = bytes(ipfsHash).length;
        require(len >= 0 && len <= MAX_STRING_LENGTH, "Invalid IPFS hash length");
    }

    function _validateTitleLength(string calldata title) internal pure {
        uint256 len = bytes(title).length;
        require(len > 0 && len <= MAX_STRING_LENGTH, "Invalid title length");
    }

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant CONFIRM_DELIVERY_TYPEHASH = keccak256(
        "ConfirmDelivery(uint256 escrowId,address buyer,address seller,address arbiter,address token,uint256 amount,uint256 depositTime,uint256 deadline,uint256 nonce)"
    );

    bytes32 private constant REQUEST_CANCEL_TYPEHASH = keccak256(
        "RequestCancel(uint256 escrowId,address buyer,address seller,address arbiter,address token,uint256 amount,uint256 depositTime,uint256 deadline,uint256 nonce)"
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

    function _calculateMinimumAmount(uint8 decimals) internal pure returns (uint256) {
        return 10 * (10 ** decimals);
    }

    function _computeFeeAndNet(
        uint256 amount,
        uint8 tokenDecimals,
        bool applyFee
    ) internal pure returns (uint256 netAmount, uint256 feeTaken) {
        uint256 minFee = 10 ** (tokenDecimals > 2 ? tokenDecimals - 2 : 0);

        if (applyFee) {
            uint256 calculatedFee = (amount * _FEE_BPS) / BPS_DENOMINATOR;
            feeTaken = calculatedFee >= minFee ? calculatedFee : minFee;
            require(feeTaken < amount, "Amount too small for fee");
            netAmount = amount - feeTaken;
        } else {
            feeTaken = 0;
            netAmount = amount;
        }
    }

    function _setFinalState(uint256 escrowId, State newState) internal {
        EscrowDeal storage deal = escrows[escrowId];
        deal.state = newState;

        if (emergencyRecoveryInitiatedAt[escrowId] != 0) {
            delete emergencyRecoveryInitiatedAt[escrowId];
            delete emergencyRecoveryStateAtInit[escrowId];
            emit EmergencyRecoveryCancelled(escrowId);
        }
    }

    function _proposePayout(
        uint256 escrowId,
        address recipient,
        bool applyFee
    ) internal returns (uint256 netAmount, uint256 feeTaken) {
        EscrowDeal storage deal = escrows[escrowId];

        if (applyFee) {
            PalindromeEscrowWallet wallet = PalindromeEscrowWallet(deal.wallet);
            netAmount = wallet.netAmount();
            feeTaken = wallet.feeAmount();

            require(netAmount + feeTaken == deal.amount, "Fee invariant mismatch");
        } else {
            netAmount = deal.amount;
            feeTaken = 0;
        }

        emit PayoutProposed(escrowId, recipient, netAmount, feeReceiver, feeTaken);
    }

    function attachSellerWalletSig(uint256 escrowId, bytes calldata sellerSig) external onlyBuyerOrSeller(escrowId) {
        emit SellerWalletSigAttached(escrowId, sellerSig);
    }   

    /**
     * @notice Create a new escrow deal using a dedicated multisig wallet (no deposit yet).
     * @dev Seller calls this to open an escrow for a given buyer and token amount.
     *      Deploys a 2-of-3 PalindromeEscrowWallet with (buyer, seller = msg.sender,
     *      arbiter) as owners. Funds must be deposited later via {deposit}.
     * @param token ERC20 token used for this escrow.
     * @param buyer Address of the buyer who will later deposit funds.
     * @param amount Amount of tokens to be escrowed (must meet the minimum).
     * @param maturityTimeDays Number of days from creation until timeout flows apply.
     * @param arbiter Address of the arbiter for dispute resolution.
     * @param title Short human-readable deal title (for frontends).
     * @param ipfsHash IPFS hash with additional deal metadata/terms.
     * @return escrowId Newly created escrow identifier.
     */
    function createEscrow(
        address token,
        address buyer,
        uint256 amount,
        uint256 maturityTimeDays,
        address arbiter,
        string calldata title,
        string calldata ipfsHash
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

        uint256 escrowId = nextEscrowId++;

        require(arbiter != msg.sender && arbiter != buyer, "Invalid arbiter");

        // compute net + fee for this escrow
        (uint256 netAmount, uint256 feeAmount) =
            _computeFeeAndNet(amount, decimals, true);

        PalindromeEscrowWallet wallet = new PalindromeEscrowWallet(
            address(this),
            escrowId,
            token,
            buyer,
            msg.sender,     // seller
            arbiter,
            feeReceiver,
            netAmount,
            feeAmount,
            2
        );

        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(wallet)
        }
        require(codeHash != bytes32(0), "Wallet code missing");
        require(address(wallet) != address(0), "Wallet creation failed");
        require(wallet.isOwner(buyer), "Buyer not owner");
        require(wallet.isOwner(msg.sender), "Seller not owner");

        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = buyer;
        deal.seller = msg.sender;
        deal.arbiter = arbiter;
        deal.wallet = address(wallet);
        deal.amount = amount;
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days);
        deal.state = State.AWAITING_PAYMENT;
        deal.tokenDecimals = decimals;

        emit WalletCreated(escrowId, address(wallet));
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
     * @notice Create a new escrow and immediately deposit funds into its multisig wallet.
     * @dev Buyer calls this to open and fund an escrow in a single transaction.
     *      Deploys a dedicated 2-of-3 PalindromeEscrowWallet with
     *      (buyer = msg.sender, seller, arbiter) as owners, then transfers
     *      `amount` of `token` from the buyer into that wallet.
     * @param token ERC20 token used for this escrow.
     * @param seller Address of the seller who will receive funds on completion.
     * @param amount Amount of tokens to escrow (must meet the minimum amount).
     * @param maturityTimeDays Number of days after deposit before timeout flows apply.
     * @param arbiter Address of the arbiter for dispute resolution.
     * @param title Short human-readable deal title (for frontends).
     * @param ipfsHash IPFS hash with additional deal metadata/terms.
     * @return escrowId Newly created escrow identifier.
     */
    function createEscrowAndDeposit(
        address token,
        address seller,
        uint256 amount,
        uint256 maturityTimeDays,
        address arbiter,
        string calldata title,
        string calldata ipfsHash
    ) external nonReentrant returns (uint256 escrowId) {
        _validateTitleLength(title);
        _validateIpfsLength(ipfsHash);
        require(token != address(0), "Token zero");
        require(seller != address(0), "Buyer zero");
        require(seller != msg.sender, "Buyer seller same");
        require(amount > 0, "Amount zero");
        require(maturityTimeDays < 3651, "Maturity too long");

        uint8 decimals = getTokenDecimals(token);
        uint256 minimumAmount = _calculateMinimumAmount(decimals);
        require(amount >= minimumAmount, "Amount too small");

        escrowId = nextEscrowId++;

        require(arbiter != msg.sender && arbiter != seller, "Invalid arbiter");

        // compute net + fee for this escrow
        (uint256 netAmount, uint256 feeAmount) =
            _computeFeeAndNet(amount, decimals, true);

        PalindromeEscrowWallet wallet = new PalindromeEscrowWallet(
            address(this),
            escrowId,
            token,
            msg.sender,     // buyer
            seller,
            arbiter,
            feeReceiver,
            netAmount,
            feeAmount,
            2
        );

        bytes32 codeHash;
        assembly {
            codeHash := extcodehash(wallet)
        }
        require(codeHash != bytes32(0), "Wallet code missing");
        require(address(wallet) != address(0), "Wallet creation failed");
        require(wallet.isOwner(msg.sender), "Buyer not owner");
        require(wallet.isOwner(seller), "Seller not owner");

        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = msg.sender;
        deal.seller = seller;
        deal.arbiter = arbiter;
        deal.wallet = address(wallet);
        deal.amount = amount;
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days);
        deal.state = State.AWAITING_PAYMENT;
        deal.tokenDecimals = decimals;

        emit WalletCreated(escrowId, address(wallet));
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

        IERC20(token).safeTransferFrom(msg.sender, address(wallet), amount);
        deal.depositTime = block.timestamp;
        deal.state = State.AWAITING_DELIVERY;

        emit PaymentDeposited(escrowId, msg.sender, amount);
    }


   /**
     * @notice Deposit the escrow amount into the dedicated multisig wallet.
     * @dev Only the buyer can call this when the escrow is in AWAITING_PAYMENT.
     *      Transfers `deal.amount` of `deal.token` from the buyer to the
     *      per-escrow wallet address and moves the escrow to AWAITING_DELIVERY.
     * @param escrowId Id of the escrow to fund with the buyer's deposit.
     */
    function deposit(uint256 escrowId) external nonReentrant escrowExists(escrowId) onlyBuyer(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_PAYMENT, "Not awaiting payment");

        IERC20(deal.token).safeTransferFrom(msg.sender, deal.wallet, deal.amount);
        deal.depositTime = block.timestamp;
        deal.state = State.AWAITING_DELIVERY;

        emit PaymentDeposited(escrowId, msg.sender, deal.amount);
    }

    /**
     * @notice Confirm delivery and complete the escrow, paying the seller.
     * @dev Only the buyer can call this once the escrow is in AWAITING_DELIVERY.
     *
     * @param escrowId Id of the escrow whose delivery is being confirmed.
     */
    function confirmDelivery(uint256 escrowId, string calldata ipfsHaesh)
        external
        nonReentrant
        escrowExists(escrowId)
        onlyBuyer(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not awaiting delivery");

        _setFinalState(escrowId, State.COMPLETE);

        (, uint256 fee) = _proposePayout(escrowId, deal.seller, true);
        emit DeliveryConfirmed(escrowId, deal.buyer, deal.seller, deal.amount, fee, ipfsHaesh);
    }


    /**
     * @notice Request cancellation of an active escrow; cancels immediately if both sides agree.
     * @dev Buyer or seller calls this to mark their intent to cancel while the escrow
     *      is in AWAITING_DELIVERY. When both buyer and seller have requested cancel,
     * @param escrowId Id of the escrow for which cancellation is requested.
     */
    function requestCancel(uint256 escrowId)
        external
        nonReentrant
        escrowExists(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];

        require(
            msg.sender == deal.buyer || msg.sender == deal.seller,
            "Only buyer or seller"
        );
        require(
            deal.state == State.AWAITING_DELIVERY,
            "Wrong state"
        );
        require(deal.depositTime != 0, "No deposit");
        require(deal.disputeStartTime == 0, "Dispute active");

        bool wasBuyerRequested = deal.buyerCancelRequested;
        bool wasSellerRequested = deal.sellerCancelRequested;

        if (msg.sender == deal.buyer) {
            require(!wasBuyerRequested, "Buyer already requested");
            deal.buyerCancelRequested = true;
        } else {
            require(!wasSellerRequested, "Seller already requested");
            deal.sellerCancelRequested = true;
        }

        if (!wasBuyerRequested || !wasSellerRequested) {
            if (deal.buyerCancelRequested && deal.sellerCancelRequested) {
                _setFinalState(escrowId, State.CANCELED);
                _proposePayout(escrowId, deal.buyer, false);
                emit Canceled(escrowId, msg.sender, deal.amount);
            } else {
                emit RequestCancel(escrowId, msg.sender);
            }
        }
    }

    /**
     * @notice Cancel an escrow by timeout and refund the buyer if the seller does not cooperate.
     * @dev Only the buyer can call this after requesting cancel and waiting past
     *      maturity + GRACE_PERIOD without a dispute or mutual cancel.
     * @param escrowId Id of the escrow to cancel by timeout.
     */
    function cancelByTimeout(uint256 escrowId) external nonReentrant escrowExists(escrowId) onlyBuyer(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];

        require(deal.state == State.AWAITING_DELIVERY, "Not awaiting delivery");
        require(deal.disputeStartTime == 0, "Dispute active");
        require(deal.buyerCancelRequested, "Must request first");
        require(!deal.sellerCancelRequested, "Mutual cancel done");
        require(deal.depositTime != 0, "No deposit");
        require(block.timestamp > deal.maturityTime + GRACE_PERIOD, "Grace period active");

       _setFinalState(escrowId, State.CANCELED);

        _proposePayout(escrowId, deal.buyer, false);

        emit Canceled(escrowId, msg.sender, deal.amount);
    }

    function startDispute(uint256 escrowId) external nonReentrant escrowExists(escrowId) onlyBuyerOrSeller(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not awaiting delivery");

        deal.state = State.DISPUTED;
        deal.disputeStartTime = block.timestamp;

        emit DisputeStarted(escrowId, msg.sender);
    }

    /**
     * @notice Post dispute evidence for the buyer or seller, stored off-chain on IPFS.
     * @dev Only a participant in the escrow can call this, and only the buyer/seller
     *      may post for their own role. Each side can submit at most one message.
     * @param escrowId Id of the disputed escrow.
     * @param role Role of the sender (must be Buyer or Seller for this function).
     * @param ipfsHash IPFS hash pointing to the dispute message/evidence document.
     */
    function submitDisputeMessage(
        uint256 escrowId,
        Role role,
        string calldata ipfsHash
    ) external nonReentrant escrowExists(escrowId) onlyParticipant(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Not disputed");

        _validateIpfsLength(ipfsHash);

        DisputeEvidence storage evidence = disputeEvidence[escrowId];
        uint256 status = disputeStatus[escrowId];

        if (role == Role.Buyer) {
            require(msg.sender == deal.buyer, "Only buyer");
            require(!evidence.buyerSubmitted, "Already submitted");
            evidence.buyerSubmitted = true;

            require((status & 1) == 0, "Already submitted");
            status |= 1;
        } else if (role == Role.Seller) {
            require(msg.sender == deal.seller, "Only seller");
            require(!evidence.sellerSubmitted, "Already submitted");
            evidence.sellerSubmitted = true;

            require((status & 2) == 0, "Already submitted");
            status |= 2;
        } else {
            revert InvalidMessageRoleForDispute();
        }

        disputeStatus[escrowId] = status;

        emit DisputeMessagePosted(escrowId, msg.sender, role, ipfsHash);
    }

    /**
    * @notice Submit the arbiter's final decision for a disputed escrow.
    * @dev Only the designated arbiter can call this and only once per escrow.
    * @param escrowId Id of the disputed escrow to resolve.
    * @param resolution Final resolution: COMPLETE (seller payout) or REFUNDED (buyer refund).
    * @param ipfsHash IPFS hash of the arbiter's decision/evidence document.
    */
    function submitArbiterDecision(
        uint256 escrowId,
        State resolution,
        string calldata ipfsHash
    ) external nonReentrant escrowExists(escrowId) onlyArbiter(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Invalid state");
        require(
            resolution == State.COMPLETE || resolution == State.REFUNDED,
            "Invalid resolution"
        );

        DisputeEvidence storage evidence = disputeEvidence[escrowId];

        bool fullEvidence = evidence.buyerSubmitted && evidence.sellerSubmitted;
        bool minEvidence = evidence.buyerSubmitted || evidence.sellerSubmitted;
        bool shortTimeout =
            block.timestamp > deal.disputeStartTime + DISPUTE_SHORT_TIMEOUT;
        bool longTimeout =
            block.timestamp >
            deal.disputeStartTime + DISPUTE_LONG_TIMEOUT + TIMEOUT_BUFFER;

        // New: enforce a minimum evidence window before arbiter can act
        require(
            block.timestamp >= deal.disputeStartTime + MIN_EVIDENCE_WINDOW,
            "Minimum evidence window not passed"
        );

        require(minEvidence || longTimeout, "Need evidence or timeout");
        require(fullEvidence || shortTimeout, "Need full evidence or timeout");
        require(!arbiterDecisionSubmitted[escrowId], "Already decided");

        evidence.arbiterDecided = true;
        arbiterDecisionSubmitted[escrowId] = true;

        _setFinalState(escrowId, resolution);

        delete disputeEvidence[escrowId];

        emit DisputeMessagePosted(escrowId, msg.sender, Role.Arbiter, ipfsHash);

        bool applyFee = (resolution == State.COMPLETE);
        address target = applyFee ? deal.seller : deal.buyer;
        (, uint256 fee) = _proposePayout(escrowId, target, applyFee);

        emit DisputeResolved(escrowId, resolution, msg.sender, deal.amount, fee);
    }

     /**
     * @notice Confirm delivery via an off-chain EIP-712 signature and release funds to the seller.
     * @dev Buyer signs a typed message off-chain; anyone (typically buyer or a relayer)
     *      can submit it. The escrow must be in AWAITING_DELIVERY.
     * @param escrowId Id of the escrow whose delivery is being confirmed.
     * @param signature Buyer EIP-712 signature authorizing delivery confirmation.
     * @param deadline Unix timestamp after which the signature is invalid.
     * @param nonce Buyer nonce for this escrow used to prevent replay.
     */
    function confirmDeliverySigned(uint256 escrowId, bytes calldata signature, uint256 deadline, uint256 nonce, string calldata ipfsHaesh) external nonReentrant escrowExists(escrowId) onlyBuyer(escrowId){
        require(deadline > block.timestamp && deadline < block.timestamp + 1 days, "Invalid deadline");

        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Invalid state");

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

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));

        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "Invalid recovery");
        require(signer == deal.buyer, "Unauthorized signer");

        _useSignature(escrowId, signature);
        _useNonce(escrowId, deal.buyer, nonce);

        _setFinalState(escrowId, State.COMPLETE);

        (, uint256 fee) = _proposePayout(escrowId, deal.seller, true);

        emit DeliveryConfirmed(escrowId, deal.buyer, deal.seller, deal.amount, fee, ipfsHaesh);
    }

    /**
     * @notice Start a dispute for an escrow using an off-chain EIP-712 signature.
     * @dev Buyer or seller calls this with their own signed message.
     *      Requirements:
     *      - Escrow must be in AWAITING_DELIVERY.
     *      - `msg.sender` must match the recovered signer (buyer or seller).
     *      - `deadline` must be in the future and at most 1 day from now.
     *      - `nonce` must be unused for this (escrowId, signer) pair.
     *      Effects:
     *      - Marks the signature and nonce as used for replay protection.
     *      - Sets state to DISPUTED and records `disputeStartTime`.
     * @param escrowId Id of the escrow to dispute.
     * @param signature Buyer/seller EIP-712 signature authorizing the dispute.
     * @param deadline Unix timestamp after which the signature is invalid.
     * @param nonce Per-signer nonce for this escrow used to prevent replay.
     */
    function startDisputeSigned(uint256 escrowId, bytes calldata signature, uint256 deadline, uint256 nonce) external nonReentrant escrowExists(escrowId) onlyBuyerOrSeller(escrowId) {
        require(deadline > block.timestamp && deadline < block.timestamp + 1 days, "Invalid deadline");

        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Invalid state");

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

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));

        address signer = ECDSA.recover(digest, signature);

        require(signer != address(0), "Invalid recovery");
        require((signer == deal.buyer) || (signer == deal.seller), "Unauthorized signer");

        _useSignature(escrowId, signature);
        _useNonce(escrowId, msg.sender, nonce);

        deal.state = State.DISPUTED;
        deal.disputeStartTime = block.timestamp;

        emit DisputeStarted(escrowId, signer);
    }

    function initiateEmergencyRecovery(uint256 escrowId)
        external
        nonReentrant
        escrowExists(escrowId)
        onlyBuyerOrSeller(escrowId)
    {
        EscrowDeal storage deal = escrows[escrowId];

        require(deal.state == State.AWAITING_DELIVERY, "Invalid state for recovery");

        emergencyRecoveryInitiatedAt[escrowId] = block.timestamp;
        emergencyRecoveryStateAtInit[escrowId] = deal.state;

        emit EmergencyRecoveryInitiated(escrowId, block.timestamp);
    }


    function executeEmergencyRecovery(uint256 escrowId)
        external
        nonReentrant
        escrowExists(escrowId)
        onlyBuyerOrSeller(escrowId)
    {
        uint256 initiatedAt = emergencyRecoveryInitiatedAt[escrowId];
        require(initiatedAt != 0, "Not initiated");
        require(
            block.timestamp >= initiatedAt + EMERGENCY_RECOVERY_DELAY,
            "Recovery delay not passed"
        );

        EscrowDeal storage deal = escrows[escrowId];

        require(
            deal.state == State.AWAITING_DELIVERY,
            "Not recoverable state"
        );
        require(
            emergencyRecoveryStateAtInit[escrowId] == State.AWAITING_DELIVERY,
            "State changed since initiation"
        );

        _setFinalState(escrowId, State.REFUNDED);
        _proposePayout(escrowId, deal.buyer, false);

        emit EmergencyRecoveryExecuted(escrowId, deal.buyer, deal.amount);
    }
}