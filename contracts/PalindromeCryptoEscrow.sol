// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";


/// @dev PalindromeCryptoEscrow contract handles the creation and management of escrow deals, ensuring secure transactions between buyers and sellers with the option for dispute resolution.
contract PalindromeCryptoEscrow is ReentrancyGuard, Ownable2Step {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    enum State { AWAITING_PAYMENT, AWAITING_DELIVERY, DISPUTED, COMPLETE, REFUNDED, CANCELED }
    enum Role { None, Buyer, Seller, Arbiter }

    uint256 private constant _FEE_BPS = 100; 
    uint256 public constant DISPUTE_SHORT_TIMEOUT = 7 days;
    uint256 public constant DISPUTE_LONG_TIMEOUT = 30 days;
    uint256 public constant TIMEOUT_BUFFER = 1 hours;
    uint256 constant GRACE_PERIOD = 6 hours;

    struct EscrowDeal {
        address token;
        address buyer;
        address seller;
        address arbiter;
        uint256 amount;
        uint256 depositTime;
        uint256 maturityTime;
        uint256 disputeStartTime; 
        State state;
        bool buyerCancelRequested;
        bool sellerCancelRequested;
        bool buyerWithdrawn;    
        bool sellerWithdrawn; 
    }

    struct Nonces {
        uint256 buyer;
        uint256 seller;
        uint256 arbiter;
    }

    uint256 public nextEscrowId;

    mapping(uint256 escrowId => EscrowDeal) public escrows;
    mapping(address tokenAddress => bool isAllowed) public allowedTokens;
    mapping(uint256 escrowId => uint256 status) public disputeStatus;
    mapping(uint256 escrowId => mapping(address user => uint256 amount)) public withdrawable;
    mapping(address => uint256) public feePool;
    mapping(uint256 escrowId => Nonces) public escrowsNonces; 
    mapping(bytes32 => bool) public usedSignatures;
    mapping(uint256 => bool) public arbiterDecisionSubmitted;
    mapping(address token => mapping(address user => uint256 amount)) public aggregatedBalance;


    error InvalidMessageRoleForDispute();
    error InvalidState();
    error Unauthorized();
    error InsufficientBalance();
    error ZeroAmount();

    // ---- Events ----
    event TokenAllowed(address indexed token, bool allowed);
    event EscrowCreated(
        uint256 indexed escrowId,
        address indexed buyer,
        address indexed seller,
        address token,
        uint256 amount,
        address arbiter,
        uint256 maturityTimeDays,
        string title,
        string ipfsHash
    );
    event PaymentDeposited(uint256 indexed escrowId, address indexed buyer, uint256 amount);
    event DeliveryConfirmed(uint256 indexed escrowId, address indexed buyer, address indexed seller, uint256 amount, uint256 fee);
    event RequestCancel(uint256 indexed escrowId, address indexed requester);
    event Canceled(uint256 indexed escrowId, address indexed initiator, uint256 amount);
    event DisputeStarted(uint256 indexed escrowId, address indexed initiator);
    event DisputeResolved(uint256 indexed escrowId, State resolution, address arbiter, uint256 amount, uint256 fee);
    event Refunded(uint256 indexed escrowId, address indexed initiator, uint256 amount, uint256 fee);
    event DisputeMessagePosted(uint256 indexed escrowId, address indexed sender, uint256 indexed role, string ipfsHash, uint256 disputeStatus);
    event Withdrawn(address indexed token, address indexed user, uint256 amount);
    event FeesWithdrawn(address indexed token, address indexed to, uint256 amount);
    event PayoutProcessed(uint256 indexed escrowId, address indexed recipient, uint256 netAmount, uint256 fee);
    event EscrowStateChanged(uint256 indexed escrowId, State oldState, State newState);

    /// @notice Ensures that the caller is a participant in the specified escrow
    /// @param escrowId The ID of the escrow to check participant status
    modifier onlyParticipant(uint256 escrowId) {
            require(msg.sender == escrows[escrowId].buyer || msg.sender == escrows[escrowId].seller || msg.sender == escrows[escrowId].arbiter, "Not a participant in escrow") ;
    _;
    }   

    /// @notice Ensures that the function can only be called by the buyer or seller of the specified escrow
    /// @param escrowId The ID of the escrow to check participant status
    modifier onlyBuyerorSeller(uint256 escrowId) {
            require(msg.sender == escrows[escrowId].buyer || msg.sender == escrows[escrowId].seller, "Not a buyer or seller in escrow") ;
    _;
    }   

    /// @notice Ensures that the caller is the buyer of the specified escrow
    /// @param escrowId The ID of the escrow to check the buyer for
    modifier onlyBuyer(uint256 escrowId) {
        require(msg.sender == escrows[escrowId].buyer, "Only buyer allowed");
        _;
    }


    // @notice Ensures that the caller is the arbiter for the specified escrow
    // @param escrowId The ID of the escrow for which the caller must be the arbiter
    modifier onlyArbiter(uint256 escrowId) {
        require(msg.sender == escrows[escrowId].arbiter, "Only arbiter allowed");
        _;
    }

    function getWithdrawable(uint256 escrowId, address user) public view returns (uint256) {
    return withdrawable[escrowId][user];
    }   

    function getFeePool(address token) public view returns (uint256) {
        return feePool[token];
    }

    function getBuyerNonce(uint256 escrowId) public view returns (uint256) {
        return escrowsNonces[escrowId].buyer;
    }

    function getSellerNonce(uint256 escrowId) public view returns (uint256) {
        return escrowsNonces[escrowId].seller;
    }

    function getArbiterNonce(uint256 escrowId) public view returns (uint256) {
        return escrowsNonces[escrowId].arbiter;
    }

    function getTokenDecimals(address token) internal view returns (uint8) {
        try IERC20Metadata(token).decimals() returns (uint8 dec) {
            require(dec >= 6 && dec <= 18, "Unsupported decimals");
            return dec;
        } catch {
            revert("Token must implement decimals()");
        }
    }

    /// @dev Returns correct nonce for signer's role
    function _getRoleNonce(uint256 escrowId, address signer, EscrowDeal storage deal) 
        internal view returns (uint256) 
    {
        if (signer == deal.buyer) return escrowsNonces[escrowId].buyer;
        if (signer == deal.seller) return escrowsNonces[escrowId].seller;
        if (signer == deal.arbiter) return escrowsNonces[escrowId].arbiter;
        revert("Unknown signer role");
    }

    /// @dev Increments nonce for signer's role
    function _incrementRoleNonce(uint256 escrowId, address signer, EscrowDeal storage deal) 
        internal 
    {
        require(signer != address(0), "Signer cannot be the zero address");
        Nonces storage nonces = escrowsNonces[escrowId];
        if (signer == deal.buyer) nonces.buyer++;
        else if (signer == deal.seller) nonces.seller++;
        else if (signer == deal.arbiter) nonces.arbiter++;
        else revert("Unknown signer role");
    }

  /**
     * @notice Marks a raw ECDSA signature as used for a specific escrow.
     * @dev Binds the signature to a given `escrowId` by storing
     *      keccak256(abi.encodePacked(escrowId, signature)) in `usedSignatures`.
     *      This provides an extra per-escrow replay guard on top of EIP-712
     *      domain separation and per-escrow, per-role nonces.
     *      Also enforces low-S canonical form and valid `v` values to prevent
     *      malleable signatures from being accepted.
     * @param escrowId The escrow for which this signature is being consumed.
     * @param signature The 65-byte ECDSA signature being marked as used.
     */
    function _useSignature(uint256 escrowId, bytes calldata signature) internal {
        require(signature.length == 65, "Invalid sig length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(add(signature.offset, 0))
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Malleability protection: enforce low-S canonical form
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "Invalid signature s"
        );
        require(v == 27 || v == 28, "Invalid v");

        // Canonical key ignores v so (r,s,27) and (r,s,28) are equivalent
        bytes32 canonicalSigHash = keccak256(
            abi.encodePacked(escrowId, r, s)
        );

        require(!usedSignatures[canonicalSigHash], "Signature already used");
        usedSignatures[canonicalSigHash] = true;
    }

    function _validateIpfsLength(string calldata ipfsHash) internal pure {
        uint256 len = bytes(ipfsHash).length;
        require(len > 0 && len <= 100, "Invalid IPFS hash length");
    }

    function _validateTitleLength(string calldata title) internal pure {
        uint256 len = bytes(title).length;
        require(len > 0 && len <= 100, "Invalid title length");
    }

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

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

    /**
    * @notice Initializes contract and sets initial allowed token.
    * @param initialAllowedToken The address of the first allowed ERC20 token.
    */
    constructor(address initialAllowedToken) {
        require(initialAllowedToken != address(0), "Token zero");
        allowedTokens[initialAllowedToken] = true;
        emit TokenAllowed(initialAllowedToken, true);
    }

    /// @notice Enables or disables a token for use in escrow deals
    /// @dev Only the contract owner can call this. Disabling a token prevents new escrows but does not affect existing ones.
    ///      Emits a {TokenAllowed} event for off-chain indexing.
    /// @param token The ERC20 token address to allow or disallow
    /// @param allowed Set to true to allow the token, false to disallow it
    function setAllowedToken(address token, bool allowed) external onlyOwner {
        require(token != address(0), "Token: zero address");
        require(IERC20(token).totalSupply() >= 0, "Token: not a contract"); // cheap ERC20 check (reverts on non-contract)
        allowedTokens[token] = allowed;
        emit TokenAllowed(token, allowed);
    }

    /**
    * @notice Creates a new escrow deal
    * @param token The ERC20 token for the escrow
    * @param buyer Address of the buyer
    * @param amount Amount of tokens to escrow
    * @param maturityTimeDays Number of days until auto-release is allowed
    * @param arbiter Optional arbiter address (use address(0) for default = contract owner)
    * @param title Deal title (for frontend)
    * @param ipfsHash Additional metadata on IPFS
    * @return escrowId The newly created escrow ID
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
        require(token != address(0), "Token cannot be zero address");
        require(allowedTokens[token], "Token not allowed");
        require(buyer != address(0), "Buyer cannot be zero address");
        require(buyer != msg.sender, "Buyer and seller cannot be same");
        require(amount > 0, "Amount must be > 0");
        require(maturityTimeDays < 3651, "Max 10 years");
       
        uint8 decimals = getTokenDecimals(token);
        uint256 minimumAmount = 10 * 10 ** decimals;  // equivalent to $10 minimum in token's smallest unit
        require(amount >= minimumAmount, "Amount less than minimum");

        uint256 escrowId = nextEscrowId++;

        address arbiterParam = arbiter == address(0) ? owner() : arbiter;
        require(arbiterParam != msg.sender && arbiterParam != buyer, "Invalid arbiter");
        
        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = buyer;
        deal.seller = msg.sender;
        deal.arbiter = arbiterParam;
        deal.amount = amount;
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days); 
        deal.state = State.AWAITING_PAYMENT;  
        deal.buyerWithdrawn = false; 
        deal.sellerWithdrawn = false; 

        escrowsNonces[escrowId] = Nonces({buyer: 0, seller: 0, arbiter: 0});  

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

    /* @param token The ERC20 token for the escrow
    * @param seller Address of the seller (use address(0) to default to msg.sender)
    * @param amount Amount of tokens to escrow (must be >= 10 * 10^decimals)
    * @param maturityTimeDays Number of days until auto-release is allowed (max 3650 = ~10 years)
    * @param arbiter Optional arbiter address (use address(0) for default = contract owner)
    * @param title Deal title (for frontend display)
    * @param ipfsHash Additional metadata on IPFS (deal description, terms, etc.)
    * @return escrowId The newly created escrow ID
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
        require(token != address(0), "Token cannot be zero address");
        require(allowedTokens[token], "Token not allowed");
        require(seller != address(0), "Buyer cannot be zero address");
        require(seller != msg.sender, "Buyer and seller cannot be same");
        require(amount > 0, "Amount must be > 0");
        require(maturityTimeDays < 3651, "Max 10 years");

        uint8 decimals = getTokenDecimals(token);
        uint256 minimumAmount = 10 * 10 ** decimals;
        if (amount < minimumAmount) revert("Amount less than minimum");
  
        escrowId = nextEscrowId++;

        address arbiterParam = arbiter == address(0) ? owner() : arbiter;
        require(arbiterParam != msg.sender && arbiterParam != seller, "Invalid arbiter");

        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = msg.sender;
        deal.seller = seller;
        deal.arbiter = arbiterParam;
        deal.amount = amount;
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days);
        deal.state = State.AWAITING_PAYMENT;

        address buyer = msg.sender;

        escrowsNonces[escrowId] = Nonces({buyer: 0, seller: 0, arbiter: 0});

        emit EscrowCreated(
            escrowId,
            buyer,
            seller,
            token,
            amount,
            arbiter,
            maturityTimeDays,
            title,
            ipfsHash
        );

        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(buyer, address(this), amount);
        uint256 balanceAfter = IERC20(token).balanceOf(address(this));

        uint256 actualReceived = balanceAfter - balanceBefore;
        if (actualReceived != amount) revert("Fee-on-transfer tokens not supported");

        deal.amount = actualReceived;
        deal.depositTime = block.timestamp;
        deal.state = State.AWAITING_DELIVERY;

        emit PaymentDeposited(escrowId, buyer, actualReceived);
    }

    /*
    * @notice Handles escrow payout with protocol fee accrual and LP minting.
    * @dev Protocol fee is added to feePool, LP tokens are minted to the owner.
    * @param token Token address paid.
    * @param recipient Net payout recipient (seller/buyer).
    * @param amount Gross payout amount.
    * @return fee Protocol fee accrued.
    */
    function _escrowPayout(
        uint256 escrowId,
        address token,
        address recipient,
        uint256 amount,
        bool applyFee
    ) internal returns (uint256 feeTaken) {
        require(recipient != address(0), "Recipient zero");
        require(amount > 0, "Amount zero");

        uint8 decimals = getTokenDecimals(token);
        uint256 minFee = 10 ** (decimals > 2 ? decimals - 2 : 0);

        uint256 netAmount;

        if (applyFee) {
            uint256 calculatedFee = (amount * _FEE_BPS) / 10_000;
            feeTaken = calculatedFee >= minFee ? calculatedFee : minFee;

            if (feeTaken >= amount) {
                feeTaken = 0;
                netAmount = amount;
            } else {
                netAmount = amount - feeTaken;
            }

            withdrawable[escrowId][recipient] += netAmount;
            aggregatedBalance[token][recipient] += netAmount;
            feePool[token] += feeTaken;
        } else {
            feeTaken = 0;
            netAmount = amount;
            withdrawable[escrowId][recipient] += amount;
            aggregatedBalance[token][recipient] += amount;
        }

        emit PayoutProcessed(escrowId, recipient, netAmount, feeTaken);
    }

    /**
    * @notice Withdraws the seller's full accumulated balance for a specific ERC20 token
    *         across all completed/refunded/canceled escrows.
    * @dev Uses `aggregatedBalance[token][msg.sender]` as the single monetary
    *      source of truth. Any per-escrow withdrawals must subtract from this
    *      aggregate, so that each token unit can only be withdrawn once,
    *      regardless of whether the user calls `withdraw` (per-escrow) or
    *      `withdrawAll` (aggregate).
    * @param token The ERC20 token address for which the caller (seller)
    *              wants to withdraw their entire accumulated balance.
    */
    function withdrawAll(address token) external nonReentrant {
        uint256 amount = aggregatedBalance[token][msg.sender];
        require(amount > 0, "Nothing to withdraw");

        aggregatedBalance[token][msg.sender] = 0;
        emit Withdrawn(token, msg.sender, amount);

        IERC20(token).safeTransfer(msg.sender, amount);
    }


    /**
    * @notice Withdraws escrowed funds after resolution.
    * @dev Burns both the per-escrow balance and the corresponding portion of
    *      `aggregatedBalance` to prevent double-withdraw via `withdrawAllSeller`.
    */
    function withdraw(uint256 escrowId) external nonReentrant onlyBuyerorSeller(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];

        require(
            deal.state == State.CANCELED ||
            deal.state == State.COMPLETE ||
            deal.state == State.REFUNDED,
            "Withdrawals only after escrow ends"
        );

        if (deal.state == State.COMPLETE) {
            require(msg.sender == deal.seller, "Only seller can withdraw after completion");
        } else {
            require(msg.sender == deal.buyer, "Only buyer can withdraw after refund/cancel");
        }

        uint256 amount = withdrawable[escrowId][msg.sender];
        require(amount > 0, "Nothing to withdraw");

        uint256 currentAgg = aggregatedBalance[deal.token][msg.sender];
        require(currentAgg >= amount, "Insufficient aggregate balance");

        withdrawable[escrowId][msg.sender] = 0;
        aggregatedBalance[deal.token][msg.sender] = currentAgg - amount;

        if (msg.sender == deal.buyer) {
            deal.buyerWithdrawn = true;
        } else {
            deal.sellerWithdrawn = true;
        }

        emit Withdrawn(deal.token, msg.sender, amount);
        IERC20(deal.token).safeTransfer(msg.sender, amount);
    }

    /// @notice Allows the contract owner (recommended: multisig) to withdraw all accumulated protocol fees for a specific token
    /// @dev    Fees are collected from successful escrows (1% by default). This function transfers the entire
    ///         accumulated fee balance for the given token to the current owner. Reentrancy-protected.
    ///         Emits a FeesWithdrawn event for off-chain indexing and transparency.
    /// @param token The ERC20 token address for which to withdraw accumulated fees (must be an allowed token)
    function withdrawFees(address token) external nonReentrant onlyOwner {
        uint256 amount = feePool[token];
        require(amount > 0, "No fees accumulated");
        feePool[token] = 0;
        IERC20(token).safeTransfer(owner(), amount);
        emit FeesWithdrawn(token, owner(), amount);
    }

    /**
     * @notice Deposits the specified amount into the escrow for the given escrowId.
     * @dev Deposits the specified amount of tokens into the escrow.
     * The function requires the escrow to be in the AWAITING_PAYMENT state and the token to be allowed.
     * It checks the allowance and ensures the transfer amount matches the expected deposit.
     * Updates the escrow state to AWAITING_DELIVERY upon successful deposit.
     * Emits a PaymentDeposited event.
     * @param escrowId The ID of the escrow deal.
     */
    function deposit(uint256 escrowId) external nonReentrant onlyBuyer(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_PAYMENT, "Not AWAITING_PAYMENT");
        require(allowedTokens[deal.token], "Token not allowed anymore");
        
        uint256 balanceBefore = IERC20(deal.token).balanceOf(address(this));
        IERC20(deal.token).safeTransferFrom(msg.sender, address(this), deal.amount);
        uint256 balanceAfter = IERC20(deal.token).balanceOf(address(this));

        uint256 actualReceived = balanceAfter - balanceBefore;
        require(actualReceived == deal.amount, "Fee-on-transfer tokens not supported");

        deal.amount = actualReceived;      
        deal.depositTime = block.timestamp;
        deal.state = State.AWAITING_DELIVERY;
        emit PaymentDeposited(escrowId, msg.sender, actualReceived);
    }


    /**
     * @notice Confirms the delivery of the escrow and completes the transaction.
     * @dev Confirms the delivery of the escrowed item, changes the state to COMPLETE, 
     * and processes the payout with a fee to the seller.
     * @param escrowId The ID of the escrow deal to confirm delivery for.
     */
    function confirmDelivery(uint256 escrowId) external nonReentrant onlyBuyer(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not AWAITING_DELIVERY");
        uint256 fee = _escrowPayout(escrowId, deal.token, deal.seller, deal.amount, true);
        deal.state = State.COMPLETE;
        emit DeliveryConfirmed(escrowId, deal.buyer, deal.seller, deal.amount, fee);
    }

    /**
     * @notice Allows the buyer or seller to request the cancellation of an escrow if both parties agree.
     * @dev Allows the buyer or seller to request a cancellation of the escrow.
     * The function checks if both parties have requested cancellation and processes it if true.
     * Emits a RequestCancel event and, if both parties agree, a Canceled event.
     * @param escrowId The ID of the escrow to be canceled.
     */
    function requestCancel(uint256 escrowId) external nonReentrant onlyBuyerorSeller(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not AWAITING_DELIVERY");
        if (msg.sender == deal.buyer) {
            deal.buyerCancelRequested = true; 
        } else {
            deal.sellerCancelRequested = true;
        }
        emit RequestCancel(escrowId, msg.sender);
        /// @notice Handles the cancellation of a deal when both buyer and seller have requested it
        /// @dev Calculates the fee and updates the deal state to CANCELED
        if (deal.buyerCancelRequested && deal.sellerCancelRequested) {
            _escrowPayout(escrowId, deal.token, deal.buyer, deal.amount, false);
            deal.state = State.CANCELED;
            emit Canceled(escrowId, msg.sender, deal.amount);
        }
    }

    /**
     * @notice Cancels the escrow by timeout if conditions are met.
     * @dev Cancels an escrow by timeout if the maturity period has been reached.
     * Requirements:
     * - The escrow must be in the AWAITING_DELIVERY state.
     * - The buyer must have requested cancellation.
     * - The seller must not have requested cancellation.
     * - A deposit must have been made.
     * - A maturity time must be set.
     * - The current time must be greater than the deposit time plus the maturity period.
     * Emits a {Canceled} event.
     */
    function cancelByTimeout(uint256 escrowId) external nonReentrant onlyBuyer(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not AWAITING_DELIVERY");
        require(deal.disputeStartTime == 0, "Cannot cancel after dispute started");
        require(deal.buyerCancelRequested, "Buyer must request cancellation");
        require(!deal.sellerCancelRequested, "Mutual cancel already processed");
        require(deal.depositTime != 0, "Deposit not made");
        require(block.timestamp > deal.maturityTime + GRACE_PERIOD, "Grace period not reached");

        if (deal.disputeStartTime > 0 && 
            deal.disputeStartTime > deal.maturityTime + GRACE_PERIOD) {
            revert("Late dispute cannot block timeout");
        }

        _escrowPayout(escrowId, deal.token, deal.buyer, deal.amount, false);
        deal.state = State.CANCELED;

        emit Canceled(escrowId, msg.sender, deal.amount);
    }
    /**
     * @notice Initiates a dispute for the specified escrow deal if it is in the delivery phase.
     * @dev Initiates a dispute for the specified escrow deal.
     * Can only be called by the buyer when the deal is in the delivery phase.
     * Changes the state of the deal to DISPUTED and emits a DisputeStarted event.
     * @param escrowId The ID of the escrow deal to dispute.
     */
    function startDispute(uint256 escrowId) external nonReentrant onlyBuyerorSeller(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not AWAITING_DELIVERY");
        deal.state = State.DISPUTED;
        deal.disputeStartTime = block.timestamp; 
        emit DisputeStarted(escrowId, msg.sender);
    }

    /**
     * @notice Submits a dispute message for a specific escrow by the designated role.
     * @dev Submits a dispute message for a given escrow by the specified role.
     * The function ensures that only the designated participant (buyer, seller, or arbiter)
     * can submit a message for the disputed escrow. It also checks that a message
     * has not already been submitted for the role.
     * @param escrowId The ID of the escrow.
     * @param role The role of the participant submitting the message.
     * @param ipfsHash The IPFS hash of the dispute message.
     */
    function submitDisputeMessage(uint256 escrowId, Role role, string calldata ipfsHash) external nonReentrant onlyParticipant(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Not DISPUTED");
        require(bytes(ipfsHash).length <= 100, "IPFS hash too long");
        uint256 mask;
        /// @notice Checks if the sender is the buyer and sets the mask accordingly
        if (role == Role.Buyer) {
            require(msg.sender == deal.buyer, "Only buyer can message");
            mask = uint256(1) << 0;
        /// @notice Checks if the sender is the seller and sets the appropriate mask
        /// @dev This block ensures only the seller can submit a message 
        } else if (role == Role.Seller) {
            require(msg.sender == deal.seller, "Only seller can message");
            mask = uint256(1) << 1;
        } else {
            revert InvalidMessageRoleForDispute();
        }
        require((disputeStatus[escrowId] & mask) == 0, "Already submitted message");
        disputeStatus[escrowId] |= mask;
        emit DisputeMessagePosted(escrowId, msg.sender, uint256(role), ipfsHash, disputeStatus[escrowId]);
    }

    /**
    * @notice Submits the arbiter's decision and evidence for a disputed escrow.
    * @dev Requirements for successful submission:
    *    1. Escrow must be in DISPUTED state
    *    2. Arbiter must not have posted evidence yet (checked via bitmask 0x04)
    *    3. Evidence rules (OR conditions):
    *       - Both buyer+seller evidence OR 7-day timeout passed
    *       - At least one evidence OR 30-day timeout passed
    *    4. Resolution must be COMPLETE or REFUNDED
    * @param escrowId The ID of the escrow to resolve
    * @param resolution COMPLETE (seller payout w/fee) or REFUNDED (buyer payout no fee)
    * @param ipfsHash Arbiter's decision evidence on IPFS
    */
    function submitArbiterDecision(
        uint256 escrowId,
        State resolution,
        string calldata ipfsHash
    ) external nonReentrant onlyArbiter(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        if (deal.state != State.DISPUTED) revert InvalidState();
        if (resolution != State.COMPLETE && resolution != State.REFUNDED) revert InvalidState();

        uint256 evidenceMask = 0x03;
        uint256 actualEvidence = disputeStatus[escrowId] & evidenceMask;
        bool fullEvidence = (actualEvidence == evidenceMask);
        bool minEvidence = (actualEvidence > 0);
        bool shortTimeout = (block.timestamp > deal.disputeStartTime + DISPUTE_SHORT_TIMEOUT);
        bool longTimeout = (block.timestamp > deal.disputeStartTime + DISPUTE_LONG_TIMEOUT + TIMEOUT_BUFFER);

        require(minEvidence || longTimeout, "Require evidence or 30-day timeout");
        require(fullEvidence || shortTimeout, "Require full evidence or 7-day timeout");

        require(!arbiterDecisionSubmitted[escrowId], "Decision already submitted");

        disputeStatus[escrowId] |= 0x04;
        emit DisputeMessagePosted(
            escrowId,
            msg.sender,
            uint256(Role.Arbiter),
            ipfsHash,
            disputeStatus[escrowId]
        );

        arbiterDecisionSubmitted[escrowId] = true;

        bool applyFee = (resolution == State.COMPLETE);
        address target = applyFee ? deal.seller : deal.buyer;

        delete disputeStatus[escrowId];
        deal.state = resolution;

        uint256 fee = _escrowPayout(escrowId, deal.token, target, deal.amount, applyFee);

        emit DisputeResolved(escrowId, resolution, msg.sender, deal.amount, fee);
    }

    /**
    * @notice Confirms delivery via signed meta-transaction (production hardened)
    * @dev Buyer confirms successful delivery, triggering seller payout with protocol fee (1%). 
    *      Enforces low-S malleability protection, buyer-specific nonce, chain-specific domain separation, 
    *      and 1-day signature validity window. Atomic COMPLETE state + payout execution.
    * @param escrowId Unique identifier of the escrow deal
    * @param signature ECDSA signature (65 bytes: r=32, s=32, v=1) over domain-separated struct hash
    * @param deadline Unix timestamp after which signature expires (must be ≤ now + 1 day)
    * @param nonce Current buyer nonce (prevents replay across signatures)
    */
    function confirmDeliverySigned(
        uint256 escrowId,
        bytes calldata signature,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant {
        require(deadline > block.timestamp && deadline < block.timestamp + 1 days, "Invalid or expired signature");

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

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );
        
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "Invalid recovery");
        require(signer == deal.buyer, "Unauthorized signer");

         _useSignature(escrowId, signature);

        uint256 expectedNonce = _getRoleNonce(escrowId, deal.buyer, deal);
        require(nonce == expectedNonce, "Invalid nonce");
      
        uint256 fee = _escrowPayout(escrowId, deal.token, deal.seller, deal.amount, true);
        deal.state = State.COMPLETE;

        _incrementRoleNonce(escrowId, deal.buyer, deal);
        
        emit DeliveryConfirmed(escrowId, deal.buyer, deal.seller, deal.amount, fee);
    }

    /**
    * @notice Requests escrow cancellation via signed meta-transaction (production hardened)
    * @dev Buyer or seller can request cancel; requires both parties to complete mutual cancellation. 
    *      Enforces low-S malleability protection, per-role nonces, chain-specific domain separation, 
    *      and 1-day signature validity window. Atomic mutual cancel + refund if both have requested.   
    * @param escrowId Unique identifier of the escrow deal
    * @param signature ECDSA signature (65 bytes: r=32, s=32, v=1) over domain-separated struct hash
    * @param deadline Unix timestamp after which signature expires (must be ≤ now + 1 day)
    * @param nonce Current nonce for signer's role (prevents replay across signatures)
    */
    function requestCancelSigned(
        uint256 escrowId,
        bytes calldata signature,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant {
        require(deadline > block.timestamp && deadline < block.timestamp + 1 days, "Invalid or expired signature");

        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Invalid state");
        require(msg.sender == deal.buyer || msg.sender == deal.seller, "Not participant");
        

        bytes32 structHash = keccak256(
            abi.encode(
                REQUEST_CANCEL_TYPEHASH,
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
            (signer == deal.buyer && msg.sender == deal.buyer) ||
            (signer == deal.seller && msg.sender == deal.seller),
            "Signature mismatch"
        );
        
         _useSignature(escrowId, signature);

        uint256 expectedNonce = _getRoleNonce(escrowId, msg.sender, deal);
        require(nonce == expectedNonce, "Invalid nonce");
         _incrementRoleNonce(escrowId, msg.sender, deal);

        bool wasMutual = deal.buyerCancelRequested && deal.sellerCancelRequested;
        if (signer == deal.buyer) {
            deal.buyerCancelRequested = true;
        } else {
            deal.sellerCancelRequested = true;
        }
        
        emit RequestCancel(escrowId, signer);
        
        if (!wasMutual && deal.buyerCancelRequested && deal.sellerCancelRequested) {
            _escrowPayout(escrowId, deal.token, deal.buyer, deal.amount, false);
            deal.state = State.CANCELED;
            emit Canceled(escrowId, signer, deal.amount);
        }
    }

    /**
    * @notice Initiates dispute via signed meta-transaction (production hardened)
    * @dev Buyer or seller can start dispute during AWAITING_DELIVERY phase. 
    *      Enforces low-S malleability protection, per-role nonces, chain-specific domain separation, 
    *      and 1-day signature validity window. Atomic state transition to DISPUTED + disputeStartTime set.
    * @param escrowId Unique identifier of the escrow deal
    * @param signature ECDSA signature (65 bytes: r=32, s=32, v=1) over domain-separated struct hash
    * @param deadline Unix timestamp after which signature expires (must be ≤ now + 1 day)
    * @param nonce Current nonce for signer's role (prevents replay across signatures)
    */
    function startDisputeSigned(
        uint256 escrowId,
        bytes calldata signature,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant {
        require(deadline > block.timestamp && deadline < block.timestamp + 1 days, "Invalid or expired signature");

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

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );

        address signer = ECDSA.recover(digest, signature);

        require(signer != address(0), "Invalid recovery");
        require(
            (signer == deal.buyer && msg.sender == deal.buyer) ||
            (signer == deal.seller && msg.sender == deal.seller),
            "Signature mismatch"
        );

        _useSignature(escrowId, signature);

        uint256 expectedNonce = _getRoleNonce(escrowId, msg.sender, deal);
        require(nonce == expectedNonce, "Invalid nonce");
         _incrementRoleNonce(escrowId, msg.sender, deal);

        deal.state = State.DISPUTED;
        deal.disputeStartTime = block.timestamp;
        
        emit DisputeStarted(escrowId, signer);
    }
}
