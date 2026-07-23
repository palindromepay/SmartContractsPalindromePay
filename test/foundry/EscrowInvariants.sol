// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";
import {PalindromePay} from "../../contracts/PalindromePay.sol";
import {PalindromePayWallet} from "../../contracts/PalindromePayWallet.sol";
import {PalindromePayWalletFactory} from "../../contracts/PalindromePayWalletFactory.sol";
import {USDT} from "../../contracts/USDT.sol";
import {FeeOnTransferToken} from "./mocks/FeeOnTransferToken.sol";
import {EscrowHandler, IMintableERC20} from "./EscrowHandler.sol";
import {EscrowSigUtils} from "./EscrowSigUtils.sol";

/// @notice Invariant suite over the PalindromePay escrow state machine.
///         Core property: every terminal escrow is withdrawable by its
///         beneficiary — the exact invariant the fund-lock bug violated.
contract EscrowInvariants is Test, EscrowSigUtils {
    PalindromePay internal pay;
    PalindromePayWalletFactory internal factory;
    EscrowHandler internal handler;

    address internal feeReceiver;

    function setUp() public {
        feeReceiver = makeAddr("feeReceiver");
        factory = new PalindromePayWalletFactory();
        pay = new PalindromePay(feeReceiver, address(factory));

        address[] memory tokens = new address[](3);
        tokens[0] = address(new USDT("USD Tether 6", "USDT6", 0, 6));
        tokens[1] = address(new USDT("USD Tether 18", "USDT18", 0, 18));
        tokens[2] = address(new FeeOnTransferToken(100, makeAddr("fotSink"), 18));

        handler = new EscrowHandler(pay, tokens);
        targetContract(address(handler));
    }

    // -----------------------------------------------------------------
    // Invariants
    // -----------------------------------------------------------------

    /// @dev Replica of PalindromePayWallet._isAuthorized, evaluated view-only
    ///      against the stored signatures.
    function _isAuthorized(PalindromePay.EscrowDeal memory deal, uint256 id) internal view returns (bool) {
        uint8 outcome = uint8(deal.state);
        address escrowC = address(pay);
        bool bValid = _sigIsValidFor(deal.buyerWalletSig, deal.buyer, id, deal.wallet, escrowC, outcome);
        bool sValid = _sigIsValidFor(deal.sellerWalletSig, deal.seller, id, deal.wallet, escrowC, outcome);
        bool aValid = _sigIsValidFor(deal.arbiterWalletSig, deal.arbiter, id, deal.wallet, escrowC, outcome);

        uint256 count;
        if (bValid) count++;
        if (sValid) count++;
        if (aValid) count++;
        if (count >= 2) return true;

        address beneficiary =
            deal.state == PalindromePay.State.COMPLETE ? deal.seller : deal.buyer;
        if (count == 1) {
            if (aValid) return true;
            if (bValid && beneficiary == deal.buyer) return true;
            if (sValid && beneficiary == deal.seller) return true;
        }
        return false;
    }

    /// @notice Every terminal, funded, not-yet-withdrawn escrow must satisfy
    ///         the wallet's authorization gate — i.e. funds are never locked.
    function invariant_terminalEscrowsWithdrawable() public view {
        uint256 n = handler.escrowCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 id = handler.escrowIds(i);
            PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);
            if (uint8(deal.state) < uint8(PalindromePay.State.COMPLETE)) continue;
            PalindromePayWallet wallet = PalindromePayWallet(deal.wallet);
            if (wallet.withdrawn()) continue;
            if (IMintableERC20(deal.token).balanceOf(deal.wallet) == 0) continue;

            assertTrue(
                _isAuthorized(deal, id),
                "Terminal escrow has no valid authorization: funds locked"
            );
        }
    }

    /// @notice Terminal states are absorbing (ghost recorded by the handler).
    function invariant_terminalStatesAbsorbing() public view {
        uint256 n = handler.escrowCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 id = handler.escrowIds(i);
            if (!handler.sawTerminal(id)) continue;
            assertEq(
                uint8(pay.getEscrow(id).state),
                handler.terminalStateGhost(id),
                "Escrow left a terminal state"
            );
        }
    }

    /// @notice No funds move before withdraw: wallet balance matches the
    ///         measured deposit exactly until withdrawal, then zero.
    function invariant_escrowFundsIntact() public view {
        uint256 n = handler.escrowCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 id = handler.escrowIds(i);
            PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);
            uint256 bal = IMintableERC20(deal.token).balanceOf(deal.wallet);

            if (deal.state == PalindromePay.State.AWAITING_PAYMENT) {
                assertEq(bal, 0, "Funds in wallet before deposit");
            } else if (PalindromePayWallet(deal.wallet).withdrawn()) {
                assertEq(bal, 0, "Funds left after withdraw");
            } else {
                assertEq(bal, deal.amount, "Wallet balance deviates from measured deposit");
            }
        }
    }

    /// @notice End-to-end teeth for invariant 1: after every fuzz run, every
    ///         terminal, funded, not-yet-withdrawn escrow gets an actual
    ///         withdraw() call — it must succeed, or funds are locked.
    function afterInvariant() public {
        uint256 n = handler.escrowCount();
        for (uint256 i = 0; i < n; i++) {
            uint256 id = handler.escrowIds(i);
            PalindromePay.EscrowDeal memory deal = pay.getEscrow(id);
            if (uint8(deal.state) < uint8(PalindromePay.State.COMPLETE)) continue;
            PalindromePayWallet wallet = PalindromePayWallet(deal.wallet);
            if (wallet.withdrawn()) continue;
            if (IMintableERC20(deal.token).balanceOf(deal.wallet) == 0) continue;

            vm.prank(deal.buyer);
            wallet.withdraw(); // any revert here fails the run: funds locked
            assertEq(
                IMintableERC20(deal.token).balanceOf(deal.wallet),
                0,
                "Wallet not emptied by final withdraw"
            );
        }
    }

    // -----------------------------------------------------------------
    // Deterministic smoke tests (prove the handler plumbing works, so an
    // invariant run without failures means paths were actually exercised)
    // -----------------------------------------------------------------

    function test_smokeHappyPathAndWithdraw() public {
        handler.createEscrowAndDepositAsBuyer(0, 0, 0, false, 0);
        assertEq(handler.calls("createAndDeposit_ok"), 1, "create+deposit failed");
        handler.acceptEscrowRearm(0); // buyer-created: seller must attach COMPLETE sig
        handler.confirmDelivery(0);
        assertEq(handler.calls("confirmDelivery_ok"), 1, "confirmDelivery failed");
        handler.withdrawAction(0, false);
        assertEq(handler.calls("withdraw_ok"), 1, "withdraw failed");
    }

    function test_smokeMutualCancelRefund() public {
        handler.createEscrowAsSeller(0, 0, 0, false, 0);
        assertEq(handler.calls("createEscrow_ok"), 1, "createEscrow failed");
        handler.depositAsBuyer(0);
        assertEq(handler.calls("deposit_ok"), 1, "deposit failed");
        handler.requestCancel(0, true);
        handler.requestCancel(0, false);
        assertEq(handler.calls("requestCancel_ok"), 2, "mutual cancel failed");
        assertEq(uint8(pay.getEscrow(0).state), uint8(PalindromePay.State.CANCELED));
        handler.withdrawAction(0, true);
        assertEq(handler.calls("withdraw_ok"), 1, "refund withdraw failed");
    }

    function test_smokeDisputeRefundViaArbiter() public {
        handler.createEscrowAndDepositAsBuyer(1, 0, 0, true, 500);
        handler.startDispute(0, true);
        assertEq(handler.calls("startDispute_ok"), 1, "startDispute failed");
        handler.submitEvidence(0, true);
        handler.submitEvidence(0, false);
        handler.arbiterDecide(0, false);
        assertEq(handler.calls("arbiterDecide_ok"), 1, "arbiter decision failed");
        assertEq(uint8(pay.getEscrow(0).state), uint8(PalindromePay.State.REFUNDED));
        handler.withdrawAction(0, true);
        assertEq(handler.calls("withdraw_ok"), 1, "dispute refund withdraw failed");
    }

    function test_smokeAutoReleaseAfterMaturity() public {
        handler.createEscrowAndDepositAsBuyer(2, 0, 0, false, 0);
        handler.acceptEscrowRearm(0); // buyer-created: seller must attach COMPLETE sig
        handler.warp(35 days);
        handler.autoRelease(0);
        assertEq(handler.calls("autoRelease_ok"), 1, "autoRelease failed");
        handler.withdrawAction(0, false);
        assertEq(handler.calls("withdraw_ok"), 1, "autoRelease withdraw failed");
    }

    /// @dev Coverage probe: drives the handler with pseudo-random seeds and
    ///      asserts the interesting transitions are actually reachable this
    ///      way — guarding against a silently no-op fuzz campaign.
    function test_fuzzCoverageProbe() public {
        uint256 seed;
        for (uint256 i = 0; i < 1200; i++) {
            seed = uint256(keccak256(abi.encode(i)));
            uint256 action = seed % 15;
            if (action == 0) handler.createEscrowAsSeller(seed, seed >> 8, seed >> 16, seed % 2 == 0, seed >> 24);
            else if (action == 1) handler.createEscrowAndDepositAsBuyer(seed, seed >> 8, seed >> 16, seed % 2 == 0, seed >> 24);
            else if (action == 2) handler.depositAsBuyer(seed);
            else if (action == 3) handler.acceptEscrowRearm(seed);
            else if (action == 4) handler.requestCancel(seed, seed % 2 == 0);
            else if (action == 5) handler.cancelByTimeout(seed);
            else if (action == 6) handler.confirmDelivery(seed);
            else if (action == 7) handler.confirmDeliverySignedAction(seed);
            else if (action == 8) handler.autoRelease(seed);
            else if (action == 9) handler.startDispute(seed, seed % 2 == 0);
            else if (action == 10) handler.submitEvidence(seed, seed % 2 == 0);
            else if (action == 11) handler.arbiterDecide(seed, seed % 2 == 0);
            else if (action == 12) handler.refundAfterTimeout(seed);
            else if (action == 13) handler.warp(seed);
            else handler.withdrawAction(seed, seed % 2 == 0);
        }

        assertGt(handler.calls("createEscrow_ok"), 0, "no seller-created escrows");
        assertGt(handler.calls("createAndDeposit_ok"), 0, "no buyer-created escrows");
        assertGt(handler.calls("deposit_ok"), 0, "no deposits");
        assertGt(handler.calls("acceptEscrow_ok"), 0, "no seller acceptances");
        assertGt(handler.calls("requestCancel_ok"), 0, "no cancel requests");
        assertGt(handler.calls("confirmDelivery_ok"), 0, "no delivery confirmations");
        assertGt(handler.calls("startDispute_ok"), 0, "no disputes");
        assertGt(handler.calls("arbiterDecide_ok"), 0, "no arbiter decisions");
        assertGt(handler.calls("autoRelease_ok"), 0, "no auto releases");
        assertGt(handler.calls("withdraw_ok"), 0, "no withdrawals");

        // Run the state invariants once over the whole probe population.
        invariant_terminalEscrowsWithdrawable();
        invariant_escrowFundsIntact();
        afterInvariant();
    }

    /// @dev Regression: the fund-lock interleaving. Post-fix, confirmDelivery
    ///      must reject the stale CANCELED-bound seller sig, and the seller
    ///      can recover by re-arming a COMPLETE sig via acceptEscrow.
    function test_smokeStaleCancelSigRejectedThenRecovered() public {
        handler.createEscrowAndDepositAsBuyer(0, 0, 0, false, 0);
        handler.requestCancel(0, false); // seller overwrites sig with CANCELED-bound
        assertEq(handler.calls("requestCancel_ok"), 1);

        handler.confirmDelivery(0);
        assertEq(handler.calls("confirmDelivery_revert"), 1, "stale sig was accepted");
        assertEq(uint8(pay.getEscrow(0).state), uint8(PalindromePay.State.AWAITING_DELIVERY));

        handler.acceptEscrowRearm(0);
        assertEq(handler.calls("acceptEscrow_ok"), 1, "re-arm failed");
        handler.confirmDelivery(0);
        assertEq(handler.calls("confirmDelivery_ok"), 1, "recovery confirm failed");
        handler.withdrawAction(0, false);
        assertEq(handler.calls("withdraw_ok"), 1, "recovery withdraw failed");
    }
}
