// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {PalindromePay} from "../../contracts/PalindromePay.sol";
import {PalindromePayWallet} from "../../contracts/PalindromePayWallet.sol";
import {EscrowSigUtils} from "./EscrowSigUtils.sol";

interface IMintableERC20 {
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

/// @notice Invariant-fuzzing handler: performs random but plausible actor
///         sequences against the escrow state machine. Expected contract
///         reverts are caught and counted; the handler itself only reverts on
///         a genuine safety violation (surfaced via fail_on_revert = true).
contract EscrowHandler is CommonBase, StdCheats, StdUtils, EscrowSigUtils {
    PalindromePay public immutable pay;

    uint256 internal constant BUYER_PK = 0xB0B;
    uint256 internal constant SELLER_PK = 0x5E11;
    uint256 internal constant ARBITER_PK = 0xA7B1;

    address public immutable buyer;
    address public immutable seller;
    address public immutable arbiter;

    address[] internal tokens;

    uint256[] public escrowIds;
    mapping(uint256 => bool) public sawTerminal;
    mapping(uint256 => uint8) public terminalStateGhost;
    mapping(bytes32 => uint256) public calls;

    uint256 internal nonceCounter = 1;

    bytes32 private constant CONFIRM_DELIVERY_TYPEHASH = keccak256(
        "ConfirmDelivery(uint256 escrowId,address buyer,address seller,address arbiter,address token,uint256 amount,uint256 depositTime,uint256 deadline,uint256 nonce)"
    );

    constructor(PalindromePay _pay, address[] memory _tokens) {
        pay = _pay;
        tokens = _tokens;
        buyer = vm.addr(BUYER_PK);
        seller = vm.addr(SELLER_PK);
        arbiter = vm.addr(ARBITER_PK);
    }

    function escrowCount() external view returns (uint256) {
        return escrowIds.length;
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// @dev Records terminal states and enforces that they are absorbing.
    modifier record(bytes32 key) {
        _;
        calls[key]++;
        for (uint256 i = 0; i < escrowIds.length; i++) {
            uint256 id = escrowIds[i];
            uint8 st = uint8(pay.getEscrow(id).state);
            bool terminal = st >= uint8(PalindromePay.State.COMPLETE);
            if (sawTerminal[id]) {
                require(st == terminalStateGhost[id], "INVARIANT: terminal state changed");
            } else if (terminal) {
                sawTerminal[id] = true;
                terminalStateGhost[id] = st;
            }
        }
    }

    function _pickEscrow(uint256 seed) internal view returns (uint256 id, bool ok) {
        if (escrowIds.length == 0) return (0, false);
        return (escrowIds[bound(seed, 0, escrowIds.length - 1)], true);
    }

    function _walletSig(
        uint256 pk,
        uint256 escrowId,
        address wallet,
        address participant,
        PalindromePay.State outcome
    ) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(pk, _payoutDigest(escrowId, wallet, address(pay), participant, uint8(outcome)));
        return abi.encodePacked(r, s, v);
    }

    function _pickToken(uint256 seed) internal view returns (address) {
        return tokens[bound(seed, 0, tokens.length - 1)];
    }

    function _boundAmount(uint256 seed, address token) internal view returns (uint256) {
        uint256 unit = 10 ** IMintableERC20(token).decimals();
        return bound(seed, 20 * unit, 1_000_000 * unit);
    }

    function _fund(address token, uint256 amount) internal {
        IMintableERC20(token).mint(buyer, amount);
        vm.prank(buyer);
        IMintableERC20(token).approve(address(pay), amount);
    }

    // -----------------------------------------------------------------
    // Actions: creation & funding
    // -----------------------------------------------------------------

    function createEscrowAsSeller(
        uint256 tokenSeed,
        uint256 amountSeed,
        uint256 maturitySeed,
        bool withArbiter,
        uint256 feeSeed
    ) external record("createEscrow") {
        address token = _pickToken(tokenSeed);
        uint256 amount = _boundAmount(amountSeed, token);
        uint256 maturityDays = bound(maturitySeed, 1, 30);
        address arb = withArbiter ? arbiter : address(0);
        uint16 feeBps = arb == address(0) ? 0 : uint16(bound(feeSeed, 0, 2_000));

        uint256 id = pay.nextEscrowId();
        address predicted = pay.computeWalletAddress(id);
        bytes memory sig = _walletSig(SELLER_PK, id, predicted, seller, PalindromePay.State.COMPLETE);

        vm.prank(seller);
        try pay.createEscrow(token, buyer, amount, maturityDays, arb, feeBps, "t", "ipfs", sig) {
            escrowIds.push(id);
            calls["createEscrow_ok"]++;
        } catch {
            calls["createEscrow_revert"]++;
        }
    }

    function createEscrowAndDepositAsBuyer(
        uint256 tokenSeed,
        uint256 amountSeed,
        uint256 maturitySeed,
        bool withArbiter,
        uint256 feeSeed
    ) external record("createAndDeposit") {
        address token = _pickToken(tokenSeed);
        uint256 amount = _boundAmount(amountSeed, token);
        uint256 maturityDays = bound(maturitySeed, 1, 30);
        address arb = withArbiter ? arbiter : address(0);
        uint16 feeBps = arb == address(0) ? 0 : uint16(bound(feeSeed, 0, 2_000));

        uint256 id = pay.nextEscrowId();
        address predicted = pay.computeWalletAddress(id);
        bytes memory sig = _walletSig(BUYER_PK, id, predicted, buyer, PalindromePay.State.COMPLETE);

        _fund(token, amount);
        vm.prank(buyer);
        try pay.createEscrowAndDeposit(token, seller, amount, maturityDays, arb, feeBps, "t", "ipfs", sig) {
            escrowIds.push(id);
            calls["createAndDeposit_ok"]++;
        } catch {
            calls["createAndDeposit_revert"]++;
        }
    }

    function depositAsBuyer(uint256 escrowSeed) external record("deposit") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);
        if (deal.state != PalindromePay.State.AWAITING_PAYMENT) return;

        bytes memory sig = _walletSig(BUYER_PK, id, deal.wallet, buyer, PalindromePay.State.COMPLETE);
        _fund(deal.token, deal.amount);
        vm.prank(buyer);
        try pay.deposit(id, sig) {
            calls["deposit_ok"]++;
        } catch {
            calls["deposit_revert"]++; // e.g. "Escrow expired"
        }
    }

    // -----------------------------------------------------------------
    // Actions: happy path & cancellation
    // -----------------------------------------------------------------

    function acceptEscrowRearm(uint256 escrowSeed) external record("acceptEscrow") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);

        bytes memory sig = _walletSig(SELLER_PK, id, deal.wallet, seller, PalindromePay.State.COMPLETE);
        vm.prank(seller);
        try pay.acceptEscrow(id, sig) {
            calls["acceptEscrow_ok"]++;
        } catch {
            calls["acceptEscrow_revert"]++;
        }
    }

    function requestCancel(uint256 escrowSeed, bool asBuyer) external record("requestCancel") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);

        uint256 pk = asBuyer ? BUYER_PK : SELLER_PK;
        address actor = asBuyer ? buyer : seller;
        bytes memory sig = _walletSig(pk, id, deal.wallet, actor, PalindromePay.State.CANCELED);
        vm.prank(actor);
        try pay.requestCancel(id, sig) {
            calls["requestCancel_ok"]++;
        } catch {
            calls["requestCancel_revert"]++;
        }
    }

    function cancelByTimeout(uint256 escrowSeed) external record("cancelByTimeout") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        vm.prank(buyer);
        try pay.cancelByTimeout(id) {
            calls["cancelByTimeout_ok"]++;
        } catch {
            calls["cancelByTimeout_revert"]++;
        }
    }

    function confirmDelivery(uint256 escrowSeed) external record("confirmDelivery") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);

        bytes memory sig = _walletSig(BUYER_PK, id, deal.wallet, buyer, PalindromePay.State.COMPLETE);
        vm.prank(buyer);
        try pay.confirmDelivery(id, sig) {
            calls["confirmDelivery_ok"]++;
        } catch {
            calls["confirmDelivery_revert"]++; // e.g. "Seller sig not for release"
        }
    }

    function confirmDeliverySignedAction(uint256 escrowSeed) external record("confirmDeliverySigned") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = nonceCounter++;

        bytes32 structHash = keccak256(
            abi.encode(
                CONFIRM_DELIVERY_TYPEHASH,
                id,
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
        bytes32 payDomain = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("PalindromePay")),
                keccak256(bytes("1")),
                block.chainid,
                address(pay)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", payDomain, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BUYER_PK, digest);
        bytes memory coordSig = abi.encodePacked(r, s, v);
        bytes memory walletSig = _walletSig(BUYER_PK, id, deal.wallet, buyer, PalindromePay.State.COMPLETE);

        vm.prank(seller); // relayer may be anyone
        try pay.confirmDeliverySigned(id, coordSig, deadline, nonce, walletSig) {
            calls["confirmDeliverySigned_ok"]++;
        } catch {
            calls["confirmDeliverySigned_revert"]++;
        }
    }

    function autoRelease(uint256 escrowSeed) external record("autoRelease") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        vm.prank(seller);
        try pay.autoRelease(id) {
            calls["autoRelease_ok"]++;
        } catch {
            calls["autoRelease_revert"]++;
        }
    }

    // -----------------------------------------------------------------
    // Actions: disputes
    // -----------------------------------------------------------------

    function startDispute(uint256 escrowSeed, bool asBuyer) external record("startDispute") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        vm.prank(asBuyer ? buyer : seller);
        try pay.startDispute(id) {
            calls["startDispute_ok"]++;
        } catch {
            calls["startDispute_revert"]++;
        }
    }

    function submitEvidence(uint256 escrowSeed, bool asBuyer) external record("submitEvidence") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.Role role = asBuyer ? PalindromePay.Role.Buyer : PalindromePay.Role.Seller;
        vm.prank(asBuyer ? buyer : seller);
        try pay.submitDisputeMessage(id, role, "evidence") {
            calls["submitEvidence_ok"]++;
        } catch {
            calls["submitEvidence_revert"]++;
        }
    }

    function arbiterDecide(uint256 escrowSeed, bool complete) external record("arbiterDecide") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);
        PalindromePay.State resolution =
            complete ? PalindromePay.State.COMPLETE : PalindromePay.State.REFUNDED;

        bytes memory sig = _walletSig(ARBITER_PK, id, deal.wallet, arbiter, resolution);
        vm.prank(arbiter);
        try pay.submitArbiterDecision(id, resolution, "ruling", sig) {
            calls["arbiterDecide_ok"]++;
        } catch {
            calls["arbiterDecide_revert"]++;
        }
    }

    function refundAfterTimeout(uint256 escrowSeed) external record("refundAfterTimeout") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);

        bytes memory sig = _walletSig(BUYER_PK, id, deal.wallet, buyer, PalindromePay.State.REFUNDED);
        vm.prank(buyer);
        try pay.refundAfterDisputeTimeout(id, sig) {
            calls["refundAfterTimeout_ok"]++;
        } catch {
            calls["refundAfterTimeout_revert"]++;
        }
    }

    // -----------------------------------------------------------------
    // Actions: time & withdrawal
    // -----------------------------------------------------------------

    function warp(uint256 seed) external record("warp") {
        vm.warp(block.timestamp + bound(seed, 1 hours, 45 days));
    }

    /// @dev The load-bearing runtime check: a terminal, funded, not-yet-
    ///      withdrawn escrow must ALWAYS be withdrawable. This is exactly the
    ///      property the fund-lock bug violated.
    function withdrawAction(uint256 escrowSeed, bool asBuyer) external record("withdraw") {
        (uint256 id, bool ok) = _pickEscrow(escrowSeed);
        if (!ok) return;
        PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);
        if (deal.wallet == address(0)) return;

        PalindromePayWallet wallet = PalindromePayWallet(deal.wallet);
        bool terminal = uint8(deal.state) >= uint8(PalindromePay.State.COMPLETE);
        bool alreadyWithdrawn = wallet.withdrawn();
        uint256 balBefore = IMintableERC20(deal.token).balanceOf(deal.wallet);
        address beneficiary =
            deal.state == PalindromePay.State.COMPLETE ? deal.seller : deal.buyer;
        uint256 beneficiaryBefore = IMintableERC20(deal.token).balanceOf(beneficiary);

        vm.prank(asBuyer ? deal.buyer : deal.seller);
        try wallet.withdraw() {
            calls["withdraw_ok"]++;
            require(
                IMintableERC20(deal.token).balanceOf(deal.wallet) == 0,
                "INVARIANT: wallet not emptied by withdraw"
            );
            require(
                IMintableERC20(deal.token).balanceOf(beneficiary) > beneficiaryBefore,
                "INVARIANT: beneficiary not paid"
            );
        } catch {
            require(
                !terminal || alreadyWithdrawn || balBefore == 0,
                "INVARIANT: terminal escrow not withdrawable"
            );
            calls["withdraw_revert"]++;
        }
    }
}
