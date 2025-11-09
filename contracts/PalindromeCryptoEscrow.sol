// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// PalindromeCryptoEscrow: Secure, production-grade escrow contract with gas/human-readable error optimizations
contract PalindromeCryptoEscrow is ReentrancyGuard, Ownable {
    using ECDSA for bytes32;

    enum State { AWAITING_PAYMENT, AWAITING_DELIVERY, DISPUTED, COMPLETE, REFUNDED, CANCELED }
    enum Role { None, Buyer, Seller, Arbiter }

    uint256 public constant FEE_BPS = 100; // 1%

    struct EscrowDeal {
        address token;
        address buyer;
        address seller;
        address arbiter;
        uint256 amount;
        uint256 depositTime;
        uint256 maturityTime;
        State state;
        bool buyerCancelRequested;
        bool sellerCancelRequested;
        uint256 nonce; // for replay protection
    }

    uint256 public nextEscrowId;
    mapping(uint256 => EscrowDeal) public escrows;
    mapping(address => bool) public allowedTokens;
    mapping(uint256 => uint256) public disputeStatus;

    address private immutable cachedThis = address(this);

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

    // ---- Modifiers ----
    modifier onlyParticipant(uint256 escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(msg.sender == deal.buyer || msg.sender == deal.seller, "Not a participant in escrow");
        _;
    }

    modifier onlyBuyer(uint256 escrowId) {
        require(msg.sender == escrows[escrowId].buyer, "Caller is not the buyer");
        _;
    }

    modifier onlyArbiter(uint256 escrowId) {
        require(msg.sender == escrows[escrowId].arbiter, "Caller is not the arbiter");
        _;
    }

    // ---- Constructor ----
    constructor(address initialAllowedToken) {
        require(initialAllowedToken != address(0), "Initial token address cannot be zero");
        allowedTokens[initialAllowedToken] = true;
        emit TokenAllowed(initialAllowedToken, true);
    }

    // ---- Owner functions ----
    function setAllowedToken(address token, bool allowed) external payable onlyOwner {
        require(token != address(0), "Token cannot be zero address");
        allowedTokens[token] = allowed;
        emit TokenAllowed(token, allowed);
    }

    // ---- Escrow functions ----
    function createEscrow(
        address token,
        address buyer,
        uint256 amount,
        uint256 maturityTimeDays,
        string calldata title,
        string calldata ipfsHash
    ) external returns (uint256) {
        require(token != address(0), "Token cannot be zero address");
        require(allowedTokens[token], "Token is not whitelisted/allowed");
        require(buyer != address(0), "Buyer cannot be zero address");
        require(buyer != msg.sender, "Buyer and seller cannot be the same");
        require(maturityTimeDays < 3651, "Maturity exceeds 3650 days");
        require(amount > 0, "Amount must be greater than zero");

        EscrowDeal storage deal = escrows[nextEscrowId];
        deal.token = token;
        deal.buyer = buyer;
        deal.seller = msg.sender;
        deal.arbiter = owner();
        deal.amount = amount;
        deal.depositTime = 0;
        deal.maturityTime = maturityTimeDays;
        deal.state = State.AWAITING_PAYMENT;
        deal.buyerCancelRequested = false;
        deal.sellerCancelRequested = false;
        deal.nonce = 0;

        emit EscrowCreated(
            nextEscrowId,
            buyer,
            msg.sender,
            token,
            amount,
            owner(),
            maturityTimeDays,
            title,
            ipfsHash
        );
        nextEscrowId++;
        return nextEscrowId - 1;
    }

    // --- Internal safe ERC20 transfers with clear errors ---
    function _safeTransfer(address token, address to, uint256 amount) internal {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        require(success, "ERC20 transfer failed");
        if (data.length > 0) require(abi.decode(data, (bool)), "ERC20 transfer did not return true");
    }
    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount));
        require(success, "ERC20 transferFrom failed");
        if (data.length > 0) require(abi.decode(data, (bool)), "ERC20 transferFrom did not return true");
    }

    // --- Escrow payout calculation and transfer ---
    function _escrowPayoutWithFee(address token, address to, uint256 amount) internal returns (uint256 fee) {
        fee = (amount * FEE_BPS) / 10000;
        uint256 payout = amount - fee;
        uint256 beforeBal = IERC20(token).balanceOf(cachedThis);
        if (fee > 0) _safeTransfer(token, owner(), fee);
        _safeTransfer(token, to, payout);
        uint256 afterBal = IERC20(token).balanceOf(cachedThis);
        require(beforeBal - afterBal == amount, "Payout not consistent with transfer");
    }

    function deposit(uint256 escrowId) external nonReentrant onlyBuyer(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_PAYMENT, "Escrow must be awaiting payment");
        require(IERC20(deal.token).allowance(msg.sender, cachedThis) >= deal.amount, "Escrow: allowance too low");

        uint256 balBefore = IERC20(deal.token).balanceOf(cachedThis);
        _safeTransferFrom(deal.token, msg.sender, cachedThis, deal.amount);
        uint256 balAfter = IERC20(deal.token).balanceOf(cachedThis);
        require(balAfter - balBefore == deal.amount, "Deposit mismatch after transfer");

        deal.depositTime = block.timestamp;
        deal.state = State.AWAITING_DELIVERY;
        emit PaymentDeposited(escrowId, msg.sender, deal.amount);
    }

    function confirmDelivery(uint256 escrowId) external nonReentrant onlyBuyer(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Escrow not awaiting delivery");
        uint256 fee = _escrowPayoutWithFee(deal.token, deal.seller, deal.amount);
        deal.state = State.COMPLETE;
        emit DeliveryConfirmed(escrowId, deal.buyer, deal.seller, deal.amount, fee);
    }

    function autoRelease(uint256 escrowId) external nonReentrant {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Escrow not in active delivery state");
        require(deal.depositTime != 0, "Deposit time not set");
        require(deal.maturityTime != 0, "Maturity not configured");
        require(block.timestamp >= deal.depositTime + (deal.maturityTime * 1 days), "Maturity time not yet reached");
        uint256 fee = _escrowPayoutWithFee(deal.token, deal.seller, deal.amount);
        deal.state = State.COMPLETE;
        emit AutoReleased(escrowId, deal.seller, deal.amount, fee);
    }

    function requestCancel(uint256 escrowId) external nonReentrant onlyParticipant(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Cancelation only allowed after deposit");
        if (msg.sender == deal.buyer) {
            deal.buyerCancelRequested = true;
        } else {
            deal.sellerCancelRequested = true;
        }
        emit RequestCancel(escrowId, msg.sender);

        if (deal.buyerCancelRequested && deal.sellerCancelRequested) {
            uint256 fee = _escrowPayoutWithFee(deal.token, deal.buyer, deal.amount);
            deal.state = State.CANCELED;
            emit Canceled(escrowId, msg.sender, deal.amount, fee);
        }
    }

    function cancelByTimeout(uint256 escrowId) external nonReentrant {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Escrow not in active delivery state");
        require(deal.buyerCancelRequested, "Buyer must request cancellation");
        require(!deal.sellerCancelRequested, "Mutual cancel already processed");
        require(deal.depositTime != 0, "Deposit not made");
        require(deal.maturityTime != 0, "No maturity set for time-based cancel");
        require(block.timestamp > deal.depositTime + (deal.maturityTime * 1 days), "Maturity period not reached");
        uint256 fee = _escrowPayoutWithFee(deal.token, deal.buyer, deal.amount);
        deal.state = State.CANCELED;
        emit Canceled(escrowId, msg.sender, deal.amount, fee);
    }

    function startDispute(uint256 escrowId) external nonReentrant onlyParticipant(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Dispute can only be started in delivery phase");
        deal.state = State.DISPUTED;
        emit DisputeStarted(escrowId, msg.sender);
    }

    function submitDisputeMessage(uint256 escrowId, Role role, string calldata ipfsHash) external nonReentrant {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Escrow not in disputed state");
        uint256 mask;
        if (role == Role.Buyer) {
            require(msg.sender == deal.buyer, "Only buyer may submit this message");
            mask = uint256(1) << 0;
        } else if (role == Role.Seller) {
            require(msg.sender == deal.seller, "Only seller may submit this message");
            mask = uint256(1) << 1;
        } else if (role == Role.Arbiter) {
            require(msg.sender == deal.arbiter, "Only arbiter may submit message");
            mask = uint256(1) << 2;
        } else {
            revert("Invalid message role for dispute");
        }
        require((disputeStatus[escrowId] & mask) == 0, "Already submitted message for role");
        disputeStatus[escrowId] |= mask;
        emit DisputeMessagePosted(escrowId, msg.sender, uint256(role), ipfsHash, disputeStatus[escrowId]);
    }

    function resolveDispute(uint256 escrowId, State resolution) external payable nonReentrant onlyArbiter(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Escrow not in dispute");
        require(resolution == State.COMPLETE || resolution == State.REFUNDED, "Invalid resolution");
        address target = resolution == State.COMPLETE ? deal.seller : deal.buyer;
        uint256 fee = _escrowPayoutWithFee(deal.token, target, deal.amount);
        delete disputeStatus[escrowId];
        deal.state = resolution;
        emit DisputeResolved(escrowId, resolution, msg.sender, deal.amount, fee);
    }

    function refund(uint256 escrowId) external payable nonReentrant onlyArbiter(escrowId) {
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Only refundable from delivery state");
        uint256 fee = _escrowPayoutWithFee(deal.token, deal.buyer, deal.amount);
        deal.state = State.REFUNDED;
        emit Refunded(escrowId, msg.sender, deal.amount, fee);
    }

    // --- Signature-based actions (Meta-tx) ---

    function confirmDeliverySigned(
        uint256 escrowId,
        bytes calldata signature,
        uint256 deadline,
        uint256 nonce
    ) external nonReentrant {
        require(block.timestamp <= deadline, "Signature expired");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Escrow not awaiting delivery");
        require(nonce == deal.nonce, "Invalid nonce for signature");
        bytes32 hash = keccak256(
            abi.encodePacked(address(this), escrowId, deal.buyer, deal.depositTime, nonce, deadline, "confirmDelivery")
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);
        require(signer == deal.buyer, "Invalid buyer signature");
        deal.nonce++;
        uint256 fee = _escrowPayoutWithFee(deal.token, deal.seller, deal.amount);
        deal.state = State.COMPLETE;
        emit DeliveryConfirmed(escrowId, deal.buyer, deal.seller, deal.amount, fee);
    }

    function requestCancelSigned(
        uint256 escrowId,
        address participant,
        uint256 deadline,
        bytes calldata signature,
        uint256 nonce
    ) external nonReentrant {
        require(block.timestamp <= deadline, "Signature expired");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Escrow not in delivery state");
        require(nonce == deal.nonce, "Nonce mismatch");
        require(participant == deal.buyer || participant == deal.seller, "Participant must be buyer or seller");
        bytes32 hash = keccak256(
            abi.encodePacked(address(this), escrowId, participant, deal.depositTime, deadline, nonce, "cancelRequest")
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);
        require(signer == participant, "Signature does not match participant");
        deal.nonce++;
        if (participant == deal.buyer) deal.buyerCancelRequested = true;
        else deal.sellerCancelRequested = true;
        emit RequestCancel(escrowId, participant);
        if (deal.buyerCancelRequested && deal.sellerCancelRequested) {
            uint256 fee = _escrowPayoutWithFee(deal.token, deal.buyer, deal.amount);
            deal.state = State.CANCELED;
            emit Canceled(escrowId, participant, deal.amount, fee);
        }
    }

    function startDisputeSigned(
        uint256 escrowId,
        address participant,
        uint256 deadline,
        bytes calldata signature,
        uint256 nonce
    ) external nonReentrant {
        require(block.timestamp <= deadline, "Signature expired");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Escrow must be in delivery for dispute");
        require(nonce == deal.nonce, "Nonce mismatch for dispute");
        require(participant == deal.buyer || participant == deal.seller, "Invalid participant for dispute");
        bytes32 hash = keccak256(
            abi.encodePacked(address(this), escrowId, participant, deal.depositTime, deadline, nonce, "startDispute")
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);
        require(signer == participant, "Signature does not match participant for dispute");
        deal.nonce++;
        deal.state = State.DISPUTED;
        emit DisputeStarted(escrowId, participant);
    }

    function refundSigned(
        uint256 escrowId,
        uint256 deadline,
        bytes calldata signature,
        uint256 nonce
    ) external nonReentrant {
        require(block.timestamp <= deadline, "Signature expired");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.AWAITING_DELIVERY, "Escrow must be in delivery to refund");
        require(nonce == deal.nonce, "Refund nonce mismatch");
        bytes32 hash = keccak256(
            abi.encodePacked(address(this), escrowId, deal.arbiter, deal.depositTime, deadline, nonce, "refund")
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);
        require(signer == deal.arbiter, "Signature does not match arbiter");
        deal.nonce++;
        uint256 fee = _escrowPayoutWithFee(deal.token, deal.buyer, deal.amount);
        deal.state = State.REFUNDED;
        emit Refunded(escrowId, deal.arbiter, deal.amount, fee);
    }

    function resolveDisputeSigned(
        uint256 escrowId,
        State resolution,
        uint256 deadline,
        bytes calldata signature,
        uint256 nonce
    ) external nonReentrant {
        require(block.timestamp <= deadline, "Signature expired");
        EscrowDeal storage deal = escrows[escrowId];
        require(deal.state == State.DISPUTED, "Not in dispute state");
        require(nonce == deal.nonce, "Nonce mismatch for dispute resolve");
        require(resolution == State.COMPLETE || resolution == State.REFUNDED, "Resolution type invalid");
        bytes32 hash = keccak256(
            abi.encodePacked(address(this), escrowId, deal.arbiter, deal.depositTime, deadline, nonce, "resolveDispute", resolution)
        );
        address signer = ECDSA.recover(hash.toEthSignedMessageHash(), signature);
        require(signer == deal.arbiter, "Signature does not match arbiter");
        deal.nonce++;
        address target = resolution == State.COMPLETE ? deal.seller : deal.buyer;
        uint256 fee = _escrowPayoutWithFee(deal.token, target, deal.amount);
        delete disputeStatus[escrowId];
        deal.state = resolution;
        emit DisputeResolved(escrowId, resolution, deal.arbiter, deal.amount, fee);
    }
}
