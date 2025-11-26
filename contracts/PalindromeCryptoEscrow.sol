// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./PalindromeEscrowLP.sol"; 


/// @notice Secure, production-grade escrow contract for P2P crypto settlement.
/// @dev This contract handles the creation and management of escrow deals, ensuring secure transactions between buyers and sellers with the involvement of an arbiter.
contract PalindromeCryptoEscrow is ReentrancyGuard, Ownable2Step {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    enum State { AWAITING_PAYMENT, AWAITING_DELIVERY, DISPUTED, COMPLETE, REFUNDED, CANCELED, WITHDRAWN }
    enum Role { None, Buyer, Seller, Arbiter }

    uint256 private constant _FEE_BPS = 100; //1%
    PalindromeEscrowLP public lpToken;         

    struct EscrowDeal {
        address token;
        address buyer;
        address seller;
        address arbiter;
        uint256 amount;
        uint256 depositTime;
        uint256 maturityTime;
        uint256 nonce; 
        State state;
        bool buyerCancelRequested;
        bool sellerCancelRequested;
    }

    uint256 public nextEscrowId;

    mapping(uint256 escrowId => EscrowDeal) public escrows;
    mapping(address tokenAddress => bool isAllowed) public allowedTokens;
    mapping(uint256 _disputeId => uint256 _status) public disputeStatus;
    mapping(address token => mapping(address user => uint256 amount)) public withdrawable;
    mapping(address => uint256) public feePool;   


    error InvalidMessageRoleForDispute();

    // ---- Events ----
    event TokenAllowed(address indexed token, bool allowed);
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
    event PaymentDeposited(uint256 indexed escrowId, address indexed buyer, uint256 amount);
    event DeliveryConfirmed(uint256 indexed escrowId, address indexed buyer, address indexed seller, uint256 amount, uint256 fee);
    event AutoReleased(uint256 indexed escrowId, address indexed seller, uint256 amount, uint256 fee);
    event RequestCancel(uint256 indexed escrowId, address indexed requester);
    event Canceled(uint256 indexed escrowId, address indexed initiator, uint256 amount, uint256 fee);
    event DisputeStarted(uint256 indexed escrowId, address indexed initiator);
    event DisputeResolved(uint256 indexed escrowId, State resolution, address arbiter, uint256 amount, uint256 fee);
    event Refunded(uint256 indexed escrowId, address indexed initiator, uint256 amount, uint256 fee);
    event DisputeMessagePosted(uint256 indexed escrowId, address indexed sender, uint256 indexed role, string ipfsHash, uint256 disputeStatus);
    event Withdrawn(address indexed token, address indexed user, uint256 amount);
    event FeeWithdrawn(address indexed token, address indexed to, uint256 amount);
    event PayoutWithFee(address indexed token, address indexed recipient, uint256 amount, uint256 fee);
    event FeeWithdrawnAll(address indexed owner, uint256 lpBurned);
    event EscrowArbiterChanged(uint256 indexed escrowId, address oldArbiter, address newArbiter);

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

    /// @notice Ensures that the caller is the seller of the specified escrow
    /// @param escrowId The ID of the escrow for which the caller must be the seller
    modifier onlySeller(uint256 escrowId) {
        require(msg.sender == escrows[escrowId].seller, "Only seller allowed");
        _;
    }

    // @notice Ensures that the caller is the arbiter for the specified escrow
    // @param escrowId The ID of the escrow for which the caller must be the arbiter
    modifier onlyArbiter(uint256 escrowId) {
        require(msg.sender == escrows[escrowId].arbiter, "Only arbiter allowed");
        _;
    }

    /**
    * @notice Initializes contract and sets initial allowed token.
    * @param initialAllowedToken The address of the first allowed ERC20 token.
    */
    constructor(address _lpToken, address initialAllowedToken) {
        require(_lpToken != address(0), "LP token required");
        lpToken = PalindromeEscrowLP(_lpToken);
        require(initialAllowedToken != address(0), "Token cannot be zero");
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

    /// @notice Returns how many fees (in the given token) the owner can currently claim by burning their LP tokens
    /// @dev This is a view function – it does not cost gas and is used by the frontend/dashboard
    ///      Returns 0 if no LP tokens or no fees accrued
    /// @param token The ERC20 token to check claimable fees for
    /// @return claimable Amount of `token` the owner can withdraw right now
    function previewFees(address token) external view returns (uint256 claimable) {
        uint256 lpBalance = lpToken.balanceOf(owner());
        uint256 totalSupply = lpToken.totalSupply();

        // Avoid division by zero + early return if owner has no LP
        if (lpBalance == 0 || totalSupply == 0) {
            return 0;
        }

        uint256 accrued = feePool[token];

        // Safe math: mulDiv style (rounds down – fair to protocol)
        claimable = (lpBalance * accrued) / totalSupply;
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
        require(token != address(0), "Token cannot be zero address");
        require(allowedTokens[token], "Token not allowed");
        require(buyer != address(0), "Buyer cannot be zero address");
        require(buyer != msg.sender, "Buyer and seller cannot be same");
        require(amount > 0, "Amount must be > 0");
        require(maturityTimeDays < 3651, "Max 10 years");

        if (
            arbiter == address(0) || 
            arbiter == msg.sender || 
            arbiter == buyer
        ) {
            arbiter = owner();
        }

        uint256 escrowId = nextEscrowId++;
        
        EscrowDeal storage deal = escrows[escrowId];
        deal.token = token;
        deal.buyer = buyer;
        deal.seller = msg.sender;
        deal.arbiter = arbiter;
        deal.amount = amount;
        deal.maturityTime = block.timestamp + (maturityTimeDays * 1 days); // ← fixed: store absolute timestamp
        deal.state = State.AWAITING_PAYMENT;
        deal.nonce = 0;

        emit EscrowCreated(
            escrowId,
            buyer,
            msg.sender,
            token,
            amount,
            arbiter,
            maturityTimeDays,  // keep days for event readability
            title,
            ipfsHash
        );

        return escrowId;
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
        address token,
        address recipient,
        uint256 amount,
        bool applyFee
    ) internal returns (uint256 feeTaken) {
        require(recipient != address(0), "Recipient zero");
        require(amount > 0, "Amount zero");

        if (applyFee && _FEE_BPS > 0) {
            feeTaken = (amount * _FEE_BPS) / 10000;
            uint256 payout = amount - feeTaken;

            withdrawable[token][recipient] += payout;
            feePool[token] += feeTaken;
            lpToken.mint(owner(), feeTaken); // LP represents claim on fees

            emit PayoutWithFee(token, recipient, amount, feeTaken);
        } else {
            // No fee — full amount goes to recipient
            withdrawable[token][recipient] += amount;
            feeTaken = 0;
            emit PayoutWithFee(token, recipient, amount, 0);
        }
    }


    /**
     * @notice Allows the buyer or seller to withdraw their funds from the escrow.
     * @dev Allows the buyer or seller to withdraw their funds from the escrow.
     * @param escrowId The ID of the escrow deal.
     * Requirements:
     * - The caller must be the buyer or seller of the escrow.
     * - There must be a non-zero amount available to withdraw.
     */
    function withdraw(uint256 escrowId) external nonReentrant onlyBuyerorSeller(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];

        // Escrow must be finished
        require(
            deal.state == State.CANCELED ||
            deal.state == State.COMPLETE ||
            deal.state == State.REFUNDED,
            "Withdrawals only allowed after escrow ends"
        );

        if (deal.state == State.COMPLETE) {
            require(msg.sender == deal.seller, "Only seller can withdraw after completion");
        } else if (deal.state == State.REFUNDED || deal.state == State.CANCELED) {
            require(msg.sender == deal.buyer, "Only buyer can withdraw after refund/cancel");
        }

        uint256 amount = withdrawable[deal.token][msg.sender];
        require(amount != 0, "Nothing to withdraw");

        withdrawable[deal.token][msg.sender] = 0;
        IERC20(deal.token).safeTransfer(msg.sender, amount);

        deal.state = State.WITHDRAWN;

        emit Withdrawn(deal.token, msg.sender, amount);
    }

    /// @notice Owner claims their share of fees for a specific token by burning LP tokens
    /// @dev Proportional claim based on LP ownership. Burn happens FIRST for security.
    /// @param token The ERC20 token to claim fees for (must be whitelisted)
    function withdrawFees(address token) external nonReentrant onlyOwner {
        require(allowedTokens[token], "Token not supported"); // or have a separate feeTokens set

        uint256 lpToBurn = lpToken.balanceOf(owner());
        require(lpToBurn > 0, "No LP to burn");

        uint256 totalSupply = lpToken.totalSupply();
        uint256 accrued = feePool[token];

        if (accrued == 0) {
            lpToken.burn(owner(), lpToBurn);
            emit FeeWithdrawnAll(owner(), lpToBurn);
            return;
        }

        lpToken.burn(owner(), lpToBurn);

        uint256 claimAmount = (lpToBurn * accrued) / totalSupply;

        if (claimAmount > 0) {
            feePool[token] = accrued - claimAmount;
            IERC20(token).safeTransfer(owner(), claimAmount);
            emit FeeWithdrawn(token, owner(), claimAmount);
        }

        emit FeeWithdrawnAll(owner(), lpToBurn);
    }

    /**
    * @notice Allows the contract owner to change arbiter of a specific escrow
    * @dev Useful for compliance upgrades, governance, and dispute assignment
    */
    function setEscrowArbiter(uint256 escrowId, address newArbiter) external onlyOwner {
        require(newArbiter != address(0), "New arbiter cannot be zero address");
        EscrowDeal storage deal = escrows[escrowId];
        address oldArbiter = deal.arbiter;
        deal.arbiter = newArbiter;
        emit EscrowArbiterChanged(escrowId, oldArbiter, newArbiter);
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
        require(IERC20(deal.token).allowance(msg.sender, address(this)) > deal.amount - 1, "Escrow: allowance too low");
        uint256 balBefore = IERC20(deal.token).balanceOf(address(this));
        IERC20(deal.token).safeTransferFrom(msg.sender, address(this), deal.amount);
        uint256 balAfter = IERC20(deal.token).balanceOf(address(this));
        require(balAfter - balBefore == deal.amount, "Deposit mismatch after transfer");
        deal.depositTime = block.timestamp;
        deal.state = State.AWAITING_DELIVERY;
        emit PaymentDeposited(escrowId, msg.sender, deal.amount);
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
        uint256 fee = _escrowPayout(deal.token, deal.seller, deal.amount, true);
        deal.state = State.COMPLETE;
        emit DeliveryConfirmed(escrowId, deal.buyer, deal.seller, deal.amount, fee);
    }

    /**
     * @notice Automatically releases the escrow funds to the seller if the maturity time has been reached.
     * @param escrowId The ID of the escrow deal to be released.
     * @dev Automatically releases the escrow amount to the seller if the maturity time has been reached.
     * Requirements:
     * - The escrow must be in the AWAITING_DELIVERY state.
     * - The deposit time and maturity time must be set.
     * - The current block timestamp must be greater than the deposit time plus the maturity period.
     * - Only the seller can call this function.
     * - The function is protected against reentrancy.
     */
    function autoRelease(uint256 escrowId) external nonReentrant onlySeller(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not AWAITING_DELIVERY");
        require(deal.depositTime != 0, "No deposit yet");
        
        // Now maturityTime is the absolute deadline timestamp
        require(block.timestamp > deal.maturityTime, "Maturity time not reached");

        uint256 fee = _escrowPayout(deal.token, deal.seller, deal.amount, true);
        deal.state = State.COMPLETE;

        emit AutoReleased(escrowId, deal.seller, deal.amount, fee);
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
        (msg.sender == deal.buyer) ? deal.buyerCancelRequested = true : deal.sellerCancelRequested = true;
        emit RequestCancel(escrowId, msg.sender);
        /// @notice Handles the cancellation of a deal when both buyer and seller have requested it
        /// @dev Calculates the fee and updates the deal state to CANCELED
        if (deal.buyerCancelRequested && deal.sellerCancelRequested) {
            _escrowPayout(deal.token, deal.buyer, deal.amount, false);
            deal.state = State.CANCELED;
            emit Canceled(escrowId, msg.sender, deal.amount, 0);
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
        require(deal.buyerCancelRequested, "Buyer must request cancellation");
        require(!deal.sellerCancelRequested, "Mutual cancel already processed");
        require(deal.depositTime != 0, "Deposit not made");
        require(block.timestamp > deal.maturityTime, "Maturity period not reached");

        _escrowPayout(deal.token, deal.buyer, deal.amount, false);
        deal.state = State.CANCELED;

        emit Canceled(escrowId, msg.sender, deal.amount, 0);
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
        /// @notice Checks if the sender is the arbiter and sets the mask for the arbiter role
        /// @dev This block ensures only the arbiter can submit a message and sets the appropriate mask
        } else if (role == Role.Arbiter) {
            require(msg.sender == deal.arbiter, "Only arbiter can message");
            mask = uint256(1) << 2;
        /// @notice Reverts the transaction if the message role is invalid for dispute
        /// @dev This scope block handles invalid message roles by 
        } else {
            revert InvalidMessageRoleForDispute();
        }
        require((disputeStatus[escrowId] & mask) == 0, "Already submitted message");
        disputeStatus[escrowId] |= mask;
        emit DisputeMessagePosted(escrowId, msg.sender, uint256(role), ipfsHash, disputeStatus[escrowId]);
    }

    /**
     * @notice Submits the arbiter's decision and evidence for a disputed escrow in a single transaction.
     * @dev Only callable by the arbiter of the escrow when the deal is in the DISPUTED state.
     *      Records the arbiter's dispute message, then resolves the dispute as either COMPLETE or REFUNDED.
     *      If resolution is COMPLETE the seller receives the escrowed amount (with fee applied); 
     *      if REFUNDED the buyer receives the amount (no fee). Updates withdrawable balances,
     *      clears the disputeStatus bitmask, and sets the final escrow state.
     *      Emits both {DisputeMessagePosted} and {DisputeResolved} events on success.
     * @param escrowId The ID of the escrow to resolve.
     * @param resolution The resolution state to set for the escrow (must be COMPLETE or REFUNDED).
     * @param ipfsHash The IPFS hash pointing to the arbiter's decision/evidence payload.
     */
    function submitArbiterDecision(
        uint256 escrowId,
        State resolution,
        string calldata ipfsHash
    ) external nonReentrant onlyArbiter(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];

        require(deal.state == State.DISPUTED, "Not DISPUTED");
        require(
            resolution == State.COMPLETE || resolution == State.REFUNDED,
            "Invalid resolution"
        );

        uint256 mask = uint256(1) << 2; // Arbiter bit
        require((disputeStatus[escrowId] & mask) == 0, "Already submitted message");
        disputeStatus[escrowId] |= mask;

        emit DisputeMessagePosted(
            escrowId,
            msg.sender,
            uint256(Role.Arbiter),
            ipfsHash,
            disputeStatus[escrowId]
        );

        address target = resolution == State.COMPLETE ? deal.seller : deal.buyer;
        bool applyFee = (resolution == State.COMPLETE);
        uint256 fee = _escrowPayout(deal.token, target, deal.amount, applyFee);

        delete disputeStatus[escrowId];
        deal.state = resolution;

        emit DisputeResolved(escrowId, resolution, msg.sender, deal.amount, fee);
    }


    /**
     * @notice Confirms the delivery of an item in escrow by verifying the buyer's signature.
     * @param escrowId The ID of the escrow deal.
     * @param signature The signature of the buyer.
     * @param deadline The deadline for the signature validity.
     * @param nonce The nonce used for the signature.
     * @dev Confirms the delivery of an escrow deal by verifying the buyer's signature.
     * The function checks the validity of the deadline, nonce, and signature.
     * It updates the escrow state to COMPLETE and processes the payout with a fee.
     * Emits a DeliveryConfirmed event upon successful confirmation.
     */
    function confirmDeliverySigned(
        uint256 escrowId,
        bytes calldata signature,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant onlyBuyer(escrowId) {
        uint256 MAX_SIGNATURE_WINDOW = 1 days;
        require(deadline > 0, "Invalid deadline");
        require(deadline > block.timestamp, "Deadline must be in the future");
        require(deadline < block.timestamp + MAX_SIGNATURE_WINDOW, "Deadline exceeds maximum window");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not AWAITING_DELIVERY");
        require(nonce == deal.nonce, "Invalid nonce for signature");

        bytes32 hash = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                escrowId,
                msg.sender, 
                deal.depositTime,
                deadline,
                nonce,
                "confirmDelivery"
            )
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);
        require(signer == deal.buyer, "Invalid buyer signature");
        deal.nonce++;
        uint256 fee = _escrowPayout(deal.token, deal.seller, deal.amount, true);
        deal.state = State.COMPLETE;
        emit DeliveryConfirmed(escrowId, deal.buyer, deal.seller, deal.amount, fee);
    }

    /**
     * @notice Requests the cancellation of an escrow deal.
     * @dev Verifies the signature and ensures both buyer and seller have requested cancellation.
     * @param escrowId The ID of the escrow deal.
     * @param deadline The deadline for the cancellation request.
     * @param signature The signature of the request.
     * @param nonce The nonce to prevent replay attacks.
     */
    function requestCancelSigned(
        uint256 escrowId,
        bytes calldata signature,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant onlyBuyerorSeller(escrowId){
        uint256 MAX_SIGNATURE_WINDOW = 1 days;
        require(deadline > 0, "Invalid deadline");
        require(deadline > block.timestamp, "Deadline must be in the future");
        require(deadline < block.timestamp + MAX_SIGNATURE_WINDOW, "Deadline exceeds maximum window");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not AWAITING_DELIVERY");
        require(nonce == deal.nonce, "Nonce mismatch");

        bytes32 hash = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                escrowId,
                msg.sender, 
                deal.depositTime,
                deadline,
                nonce,
                "cancelRequest"
            )
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);

        require(
            (signer == deal.buyer && msg.sender == deal.buyer) ||
            (signer == deal.seller && msg.sender == deal.seller),
            "Signature participant mismatch"
        );

        deal.nonce++;
        if (signer == deal.buyer) deal.buyerCancelRequested = true;
        else deal.sellerCancelRequested = true;

        emit RequestCancel(escrowId, signer);
        /// @notice Handles the cancellation of a deal when both buyer and seller have requested it.
        /// @dev Calculates the fee and updates the deal state to CANCELED.
        if (deal.buyerCancelRequested) {
            if (deal.sellerCancelRequested) {
                uint256 fee = _escrowPayout(deal.token, deal.buyer, deal.amount, false);
                deal.state = State.CANCELED;
                emit Canceled(escrowId, msg.sender, deal.amount, fee);
            }
        }
    }

    /** 
     * @notice Initiates a dispute for the specified escrow if conditions are met.
     * @dev Initiates a dispute for an escrow transaction. The function can only be called by the buyer.
     * The dispute must be started within a valid signature window and the nonce must match the current deal nonce.
     * The signer of the signature must be either the buyer or the seller.
     * @param escrowId The ID of the escrow transaction.
     * @param signature The signature of the buyer or seller.
     * @param deadline The deadline by which the dispute must be initiated.
     * @param nonce The current nonce of the escrow deal.
     */
    function startDisputeSigned(
        uint256 escrowId,
        bytes calldata signature,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant onlyBuyerorSeller(escrowId){
        uint256 MAX_SIGNATURE_WINDOW = 1 days;
        require(deadline > 0, "Invalid deadline");
        require(deadline > block.timestamp, "Deadline must be in the future");
        require(deadline < block.timestamp + MAX_SIGNATURE_WINDOW, "Deadline exceeds maximum window");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Not AWAITING_DELIVERY");
        require(nonce == deal.nonce, "Nonce mismatch");

        bytes32 hash = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                escrowId,
                msg.sender, 
                deal.depositTime,
                deadline,
                nonce,
                "startDispute"
            )
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);
        require(signer == deal.buyer, "Signature must be buyer");
        deal.nonce++;
        deal.state = State.DISPUTED;
        emit DisputeStarted(escrowId, signer);
    }

    /** 
     * @notice Resolves a dispute for a given escrow by verifying the arbiter's signature and updating the escrow state.
     * @dev Resolves a dispute for a given escrow by verifying the arbiter's signature.
     * The function checks the validity of the deadline, nonce, and resolution type.
     * It ensures the signature matches the arbiter's and updates the escrow state accordingly.
     * Emits a DisputeResolved event upon successful resolution.
     * @param escrowId The ID of the escrow in dispute.
     * @param resolution The desired resolution state (COMPLETE or REFUNDED).
     * @param deadline The deadline by which the resolution must be signed.
     * @param signature The arbiter's signature for the resolution.
     * @param nonce The nonce to ensure the resolution is unique.
     */
    function resolveDisputeSigned(
        uint256 escrowId,
        bytes calldata signature,
        State resolution,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant onlyArbiter(escrowId){
        uint256 MAX_SIGNATURE_WINDOW = 1 days;
        require(deadline > 0, "Invalid deadline");
        require(deadline > block.timestamp, "Deadline must be in the future");
        require(deadline < block.timestamp + MAX_SIGNATURE_WINDOW, "Deadline exceeds maximum window");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Not in dispute state");
        require(nonce == deal.nonce, "Nonce mismatch for dispute resolve");
        require(resolution == State.COMPLETE || resolution == State.REFUNDED, "Resolution type invalid");
        bytes32 hash = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                escrowId,
                msg.sender, 
                deal.depositTime,
                deadline,
                nonce,
                "resolveDispute"
            )
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);
        require(signer == deal.arbiter, "Signature does not match arbiter");
        deal.nonce++;
        address target = resolution == State.COMPLETE ? deal.seller : deal.buyer;
        uint256 fee = _escrowPayout(deal.token, target, deal.amount, true);
        delete disputeStatus[escrowId];
        deal.state = resolution;
        emit DisputeResolved(escrowId, resolution, signer, deal.amount, fee);
    }
}
