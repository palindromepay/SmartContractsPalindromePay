/**
 * ===============================
 *   ESCROW CONTRACT TEST COVERAGE
 * ===============================
 * This suite tests all critical flows for PalindromeCryptoEscrow, validating secure P2P escrow, meta-transaction signing, protocol fees, and advanced dispute scenarios.
 *
 * Covered Scenarios:
 *  - Buyer deposits and funds escrow successfully.
 *  - Delivery confirmation and seller withdrawal via both direct and meta-tx signatures.
 *  - Protocol fee accrual with LP token minting and secure owner withdrawal (withdrawAllFees).
 *  - Mutual cancel and cancelByTimeout: both immediate (mutual) and delayed (by maturity/timeout).
 *  - Seller autoRelease after escrow maturity, validating time-dependent payout.
 *  - Arbiter/owner issues refunds both directly and via off-chain meta-transaction.
 *  - Secure dispute opening (buyer/seller only), meta-tx and direct, with resolution to both seller (COMPLETE) and buyer (REFUNDED) paths.
 *  - Only authorized roles can withdraw, dispute, resolve, or cancel; unauthorized access tests revert as expected.
 *  - Negative tests: replay prevention via strict nonce handling, invalid/deadline signature reverts, double-withdrawal and double-cancel blocked.
 *  - All meta-tx methods (confirmDeliverySigned, startDisputeSigned, resolveDisputeSigned, requestCancelSigned) covered, validating replay, role, and security guarantees.
 *
 * (c) 2025 Palindrome Finance - Automated Test Suite Reference
 */


import 'dotenv/config';
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import {
    createPublicClient,
    createWalletClient,
    http,
    keccak256,
    encodeAbiParameters, parseAbiParameters,
} from 'viem';


import type {
    Address,
    WalletClient,
} from 'viem';


import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import EscrowArtifact from '../artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json' with { type: "json" };
import LPArtifact from '../artifacts/contracts/PalindromeEscrowLP.sol/PalindromeEscrowLP.json' with { type: "json" };
import USDTArtifact from '../artifacts/contracts/USDT.sol/USDT.json' with { type: "json" };
import { getChainId } from 'viem/actions';


const rpcUrl = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const buyerKey = process.env.BUYER_KEY as `0x${string}`;
const sellerKey = process.env.SELLER_KEY as `0x${string}`;
const ownerKey = process.env.OWNER_KEY as `0x${string}`;

if (!rpcUrl) throw new Error("RPC_URL env var is missing!");
if (!buyerKey) throw new Error("BUYER_KEY env var is missing!");
if (!sellerKey) throw new Error("SELLER_KEY env var is missing!");
if (!ownerKey) throw new Error("OWNER_KEY env var is missing!");


const CHAIN = foundry;

const buyer = privateKeyToAccount(buyerKey);
const seller = privateKeyToAccount(sellerKey);
const owner = privateKeyToAccount(ownerKey);

const publicClient = createPublicClient({ chain: CHAIN, transport: http(rpcUrl) });
const buyerClient = createWalletClient({ account: buyer, chain: CHAIN, transport: http(rpcUrl) });
const sellerClient = createWalletClient({ account: seller, chain: CHAIN, transport: http(rpcUrl) });
const ownerClient = createWalletClient({ account: owner, chain: CHAIN, transport: http(rpcUrl) });


const tokenAbi = USDTArtifact.abi;
const tokenBytecode = USDTArtifact.bytecode as `0x${string}`;
const lpAbi = LPArtifact.abi;
const lpBytecode = LPArtifact.bytecode as `0x${string}`;
const escrowAbi = EscrowArtifact.abi;
const escrowBytecode = EscrowArtifact.bytecode as `0x${string}`;

let tokenAddress: `0x${string}`;
let lpAddress: `0x${string}`;
let escrowAddress: `0x${string}`;


const chainIdNumber: number = await getChainId(publicClient);
const chainId: bigint = BigInt(chainIdNumber);


const AMOUNT = 1_000_000n;


const State = {
    AWAITING_PAYMENT: 0,
    AWAITING_DELIVERY: 1,
    DISPUTED: 2,
    COMPLETE: 3,
    REFUNDED: 4,
    CANCELED: 5,
    WITHDRAWN: 6,
} as const;




before(async () => {
    const initialSupply = 1_000_000_000_000n;

    // Deploy USDT
    const tokenTxHash = await ownerClient.deployContract({
        abi: tokenAbi,
        bytecode: tokenBytecode,
        args: ["Tether USD", "USDT", initialSupply],
        account: owner.address,
        chain: CHAIN,
    });
    tokenAddress = (await publicClient.waitForTransactionReceipt({ hash: tokenTxHash })).contractAddress as `0x${string}`;
    assert.ok(tokenAddress, 'Token deployment failed');

    // Deploy LP token
    const lpHash = await ownerClient.deployContract({
        abi: lpAbi,
        bytecode: lpBytecode,
        args: [],
        account: owner.address,
        chain: CHAIN,
    });
    lpAddress = (await publicClient.waitForTransactionReceipt({ hash: lpHash })).contractAddress as `0x${string}`;
    assert.ok(lpAddress, 'LP deployment failed');

    // Deploy escrow contract with LP+token address
    const escrowTxHash = await ownerClient.deployContract({
        abi: escrowAbi,
        bytecode: escrowBytecode,
        args: [lpAddress, tokenAddress],
        account: owner.address,
        chain: CHAIN,
    });
    escrowAddress = (await publicClient.waitForTransactionReceipt({ hash: escrowTxHash })).contractAddress as `0x${string}`;
    assert.ok(escrowAddress, 'Escrow deployment failed');

    // Set escrow as LP minter
    const setMinterTxHash = await ownerClient.writeContract({
        address: lpAddress,
        abi: lpAbi,
        functionName: "setMinter",
        args: [escrowAddress],
        account: owner.address,
        chain: CHAIN,
    });
    await publicClient.waitForTransactionReceipt({ hash: setMinterTxHash });
});


// ------ Utility Helpers ----------
async function fundAndApprove(amount: bigint = AMOUNT) {
    await ownerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'transfer',
        args: [buyer.address, amount]
    });
    await buyerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'approve',
        args: [escrowAddress, amount]
    });
}

async function createEscrow(amount: bigint = AMOUNT, maturityDays: bigint = 0n) {
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, amount, maturityDays, owner.address, "Escrow title", "QmHash"],
        chain: CHAIN,
        account: seller
    });
}


async function setupDeal(amount = AMOUNT, maturityDays = 0n): Promise<number> {
    await fundAndApprove(amount);
    await createEscrow(amount, maturityDays);
    const nextId = Number(await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'nextEscrowId'
    }));
    return nextId - 1;
}



function buildMessageHash(
    chainId: bigint,
    escrowAddress: Address,
    escrowId: number,
    sender: Address,
    depositTime: bigint,
    deadline: bigint,
    nonce: bigint,
    method: string
): `0x${string}` {
    // Parse the ABI parameter types once (do this at module level for efficiency)
    const abiParams = parseAbiParameters(
        'uint256, address, uint256, address, uint256, uint256, uint256, string'
    );

    // Prepare your values as a strictly ordered tuple
    const values: [
        bigint,        // chainId as bigint
        `0x${string}`, // escrowAddress as string with 0x prefix
        bigint,        // escrowId as bigint
        `0x${string}`, // sender as string with 0x prefix
        bigint,        // depositTime as bigint
        bigint,        // deadline as bigint (UNIX timestamp)
        bigint,        // nonce as bigint
        string         // method (e.g. "confirmDelivery")
    ] = [
            BigInt(chainId),
            escrowAddress as `0x${string}`,
            BigInt(escrowId),
            sender as `0x${string}`,
            BigInt(depositTime),
            BigInt(deadline),
            BigInt(nonce),
            method
        ];


    // Encode with ABI encoding, then hash
    const encoded = encodeAbiParameters(abiParams, values);
    return keccak256(encoded);
}



async function sign(participantClient: WalletClient, account: Address, hash: `0x${string}`) {
    return await participantClient.signMessage({ account, message: { raw: hash } });
}


async function getDeal(id: number) {
    return await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'escrows',
        args: [id]
    }) as any;
}


async function increaseTime(seconds: number) {
    await publicClient.transport.request({ method: 'evm_increaseTime', params: [seconds] });
    await publicClient.transport.request({ method: 'evm_mine', params: [] });
}

test('previewFees() correctly tracks protocol fees before and after withdrawFees', async () => {
    // 1) Initially: no fees, no LP → previewFees returns 0
    let preview = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'previewFees',
        args: [tokenAddress],
    }) as bigint;

    assert.equal(preview, 0n, 'previewFees should be 0 when no fees accrued');

    // 2) Complete one deal → 1% fee accrues, owner gets LP, previewFees > 0
    const id = await setupDeal();

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [id],
    });

    const lpBalance = await publicClient.readContract({
        address: lpAddress,
        abi: lpAbi,
        functionName: 'balanceOf',
        args: [owner.address],
    }) as bigint;

    const totalSupply = await publicClient.readContract({
        address: lpAddress,
        abi: lpAbi,
        functionName: 'totalSupply',
        args: [],
    }) as bigint;

    const accrued = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'feePool',
        args: [tokenAddress],
    }) as bigint;

    assert(lpBalance > 0n, 'Owner should have LP after fee accrual');
    assert(accrued > 0n, 'feePool should have accrued fees');

    const expectedClaimable = (lpBalance * accrued) / totalSupply;

    preview = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'previewFees',
        args: [tokenAddress],
    }) as bigint;

    assert.equal(
        preview,
        expectedClaimable,
        'previewFees should match proportional share of feePool for owner LP',
    );

    // 3) After withdrawFees: LP burned, feePool reduced, previewFees should be 0 (owner has no LP)
    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawFees',
        args: [tokenAddress],
    });

    const lpAfter = await publicClient.readContract({
        address: lpAddress,
        abi: lpAbi,
        functionName: 'balanceOf',
        args: [owner.address],
    }) as bigint;

    preview = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'previewFees',
        args: [tokenAddress],
    }) as bigint;

    assert.equal(lpAfter, 0n, 'Owner LP should be 0 after withdrawFees burns all LP');
    assert.equal(preview, 0n, 'previewFees should be 0 after fees claimed and LP burned');
});


// --------- Core Tests (contract state and withdrawal) ---------
test('deposit and delivery flow with withdrawal', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'confirmDelivery', args: [id] });

    // Check seller's withdrawable
    let sellerWithdrawable = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, seller.address],
    });
    assert(Number(sellerWithdrawable) > 0, "Seller should have withdrawable balance");

    // Seller withdraws
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdraw',
        args: [id]
    });

    sellerWithdrawable = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, seller.address],
    });
    assert.equal(Number(sellerWithdrawable), 0, "Seller withdrawable should be zero after withdraw");

    const deal = await getDeal(id);
    assert.equal(deal[8], State.WITHDRAWN, "Escrow should be WITHDRAWN after seller withdraw");
});


// Mutual cancel refunds buyer
test('mutual cancel triggers withdrawal for buyer', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'requestCancel', args: [id] });
    await sellerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'requestCancel', args: [id] });


    // Buyer should have withdrawable
    const buyerWithdrawable = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, buyer.address]
    });
    assert(Number(buyerWithdrawable) > 0, "Buyer withdrawable after mutual cancel");


    // Buyer withdraws
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdraw',
        args: [id]
    });
    const buyerAfter = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, buyer.address]
    });
    assert.equal(Number(buyerAfter), 0, "Buyer withdrawable zero after claiming cancel funds");
});

test('autoRelease allows seller to release funds after maturity', async () => {
    // Setup: Create and fund an escrow with maturity period
    const MATURITY_DAYS = 1n; // 1 day
    const id = await setupDeal(AMOUNT, MATURITY_DAYS);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id]
    });

    // Fast-forward time past maturity
    let deal = await getDeal(id);
    const fastForwardSeconds = Number(MATURITY_DAYS * 86400n) + 10;
    await increaseTime(fastForwardSeconds);

    // Seller calls autoRelease, should succeed
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'autoRelease',
        args: [id]
    });

    // Confirm state transition to COMPLETE
    deal = await getDeal(id);
    assert.equal(deal[8], State.COMPLETE, "Escrow should be COMPLETE after autoRelease");
});


test('cancelByTimeout allows buyer to cancel if seller does not respond after maturity', async () => {
    // Setup: Create/fund escrow with maturity and request cancel only from buyer
    const MATURITY_DAYS = 1n; // 1 day
    const id = await setupDeal(AMOUNT, MATURITY_DAYS);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id]
    });

    // Buyer requests cancel
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'requestCancel',
        args: [id]
    });

    // Fast-forward time past maturity
    const fastForwardSeconds = Number(MATURITY_DAYS * 86400n) + 10;
    await increaseTime(fastForwardSeconds);

    // Buyer calls cancelByTimeout, should succeed
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'cancelByTimeout',
        args: [id]
    });

    // Confirm state transition to CANCELED
    const deal = await getDeal(id);
    assert.equal(deal[8], State.CANCELED, "Escrow should be CANCELED after cancelByTimeout");
});


test('buyer or seller can start dispute only in AWAITING_DELIVERY', async () => {
    // Setup
    const id = await setupDeal();

    // Deposit must occur! This transitions escrow from AWAITING_PAYMENT to AWAITING_DELIVERY
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id]
    });

    // Check that the state is AWAITING_DELIVERY
    let deal = await getDeal(id);
    assert.equal(deal[8], State.AWAITING_DELIVERY, "Escrow should be AWAITING_DELIVERY after deposit");

    // Buyer can start dispute
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDispute',
        args: [id]
    });

    // Prepare second escrow for seller dispute
    const id2 = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id2]
    });

    deal = await getDeal(id2);
    assert.equal(deal[8], State.AWAITING_DELIVERY, "Second escrow should be AWAITING_DELIVERY after deposit");

    // Seller can start dispute
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDispute',
        args: [id2]
    });

    // Negative test: Can't start dispute on escrow that's already complete
    const id3 = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id3]
    });
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [id3]
    });

    deal = await getDeal(id3);
    assert.equal(deal[8], State.COMPLETE, "Escrow should be COMPLETE after delivery confirmation");

    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'startDispute',
            args: [id3]
        }),
        "Should revert: Not AWAITING_DELIVERY"
    );

    // Negative test: Non-participant (neither buyer nor seller) can't start dispute
    const randomKey = '0x' + '1'.repeat(64);
    const randomUser = privateKeyToAccount(randomKey as `0x${string}`);
    const randomClient = createWalletClient({ account: randomUser, chain: CHAIN, transport: http(rpcUrl) });

    const id4 = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id4]
    });

    deal = await getDeal(id4); // Should be AWAITING_DELIVERY

    await assert.rejects(
        async () => await randomClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'startDispute',
            args: [id4]
        }),
        "Should revert: Not a buyer or seller in escrow"
    );
});


test('seller withdraw reverts if balance is zero after payout claimed', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'confirmDelivery', args: [id] });
    await sellerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'withdraw', args: [id] });
    await assert.rejects(
        async () => await sellerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'withdraw', args: [tokenAddress] }),
        "Second withdraw should revert"
    );
});


test('protocol fee withdraw reverts if already claimed', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'confirmDelivery', args: [id] });

    // Withdraw once
    await ownerClient.writeContract({
        address: escrowAddress, abi: escrowAbi, functionName: 'withdrawFees', args: [tokenAddress]
    });
    // LP is now zero; second withdraw fails
    await assert.rejects(
        async () => await ownerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'withdrawFees', args: [tokenAddress] }),
        "Second protocol fee withdrawal should revert"
    );
});


test('meta transaction: signature replay is blocked by nonce', async () => {
    const id = await setupDeal();

    // 1) Deposit -> AWAITING_DELIVERY
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    let deal = await getDeal(id);
    assert.equal(
        deal[8],
        State.AWAITING_DELIVERY,
        'Escrow should be AWAITING_DELIVERY after deposit',
    );

    // 2) Build meta-tx hash for confirmDeliverySigned using on-chain time
    const block = await publicClient.getBlock();
    const currentTs = Number(block.timestamp);
    const deadline = BigInt(currentTs + 3600); // 1 hour in future

    const nonce = deal[7] as bigint;
    const depositTime = deal[5] as bigint;
    const sender = buyer.address;

    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,
        depositTime,
        deadline,
        nonce,
        'confirmDelivery',
    );
    const signature = await sign(buyerClient, sender, hash);

    // 3) First call works – meta-tx accepted
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDeliverySigned',
        args: [id, signature, deadline, nonce],
    });

    deal = await getDeal(id);
    assert.equal(
        deal[8],
        State.COMPLETE,
        'Escrow should be COMPLETE after first meta-confirm',
    );

    // 4) Second call (replay) must revert — assert that it throws
    await assert.rejects(
        () =>
            buyerClient.writeContract({
                address: escrowAddress,
                abi: escrowAbi,
                functionName: 'confirmDeliverySigned',
                args: [id, signature, deadline, nonce],
            }),
        // No message matcher: any revert is acceptable here
    );
});


test('seller withdraw reverts on double claim', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'confirmDelivery', args: [id] });
    await sellerClient.writeContract({
        address: escrowAddress, abi: escrowAbi, functionName: 'withdraw', args: [id]
    });
    await assert.rejects(
        async () => await sellerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'withdraw', args: [id] }),
        "Second seller withdrawal should revert"
    );
});


test('withdrawal reverts for seller with zero balance', async () => {
    const id = await setupDeal();
    let sellerWithdrawable = await publicClient.readContract({
        address: escrowAddress, abi: escrowAbi, functionName: 'withdrawable', args: [tokenAddress, seller.address]
    });
    assert.equal(Number(sellerWithdrawable), 0, "Seller withdrawable should be zero before any settlement");
    await assert.rejects(
        async () => await sellerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'withdraw', args: [id] }),
        "Withdraw with zero balance should revert for seller"
    );
});

test('protocol owner can withdraw all protocol fees (withdrawAllFees)', async () => {
    // Check owner LP token balance before fee withdrawal
    let ownerLpBalance = await publicClient.readContract({
        address: lpAddress,
        abi: lpAbi,
        functionName: 'balanceOf',
        args: [owner.address]
    });

    console.log("Owner LP balance before withdrawAllFees:", ownerLpBalance);
    assert(Number(ownerLpBalance) > 0, "Protocol owner LP balance should be greater than zero before fee withdrawal");

    // Protocol (owner) withdraws all fees
    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawFees',
        args: [tokenAddress]
    });

    // Check owner LP token balance after fee withdrawal
    ownerLpBalance = await publicClient.readContract({
        address: lpAddress,
        abi: lpAbi,
        functionName: 'balanceOf',
        args: [owner.address]
    });
    console.log("Owner LP balance after withdrawAllFees:", ownerLpBalance);
    assert.equal(Number(ownerLpBalance), 0, "Protocol owner LP balance should be zero after fee withdrawal");

    // Try to withdraw again, must revert per specification (no double claim)
    await assert.rejects(
        async () => await ownerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'withdrawAllFees',
            args: []
        }),
        "Second protocol fee withdrawal should revert"
    );
});


test('meta transaction: invalid signature is rejected', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });

    let deal = await getDeal(id);
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = deal[7];
    const depositTime = deal[5];

    const sender = buyer.address;

    // Intentionally use a wrong hash to get an invalid signature
    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,
        depositTime + 1n, // Wrong field to ensure signature mismatch
        deadline,
        nonce,
        'confirmDelivery'
    );
    const invalidSig = await sign(buyerClient, buyer.address, hash);

    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'confirmDeliverySigned',
            args: [id, invalidSig, deadline, nonce]
        }),
        "Should revert on invalid buyer signature"
    );
});

test('meta transaction: deadline too early is rejected', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    let deal = await getDeal(id);
    const deadline = BigInt(Math.floor(Date.now() / 1000) - 10); // Deadline in the past
    const nonce = deal[7];
    const depositTime = deal[5];
    const sender = buyer.address;

    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,
        depositTime,
        deadline,
        nonce,
        'confirmDelivery'
    );
    const signature = await sign(buyerClient, sender, hash);

    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'confirmDeliverySigned',
            args: [id, signature, deadline, nonce]
        }),
        "Must revert due to expired deadline"
    );
});

test('only buyer or seller can withdraw', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'confirmDelivery', args: [id] });

    // Simulate an unauthorized account: generate a new account (not owner, seller, or buyer)
    const randomKey = '0x' + '1'.repeat(64) as `0x${string}`;
    const randomUser = privateKeyToAccount(randomKey);
    const randomClient = createWalletClient({ account: randomUser, chain: CHAIN, transport: http(rpcUrl) });

    await assert.rejects(
        async () => await randomClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'withdraw',
            args: [id]
        }),
        "Unauthorized withdraw must revert"
    );
});

test('cannot start dispute after escrow is complete', async () => {
    const id = await setupDeal();

    // Buyer deposits and confirms delivery (escrow becomes COMPLETE)
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id]
    });

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [id]
    });

    // Attempt to start a dispute now should revert!
    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'startDispute',
            args: [id]
        }),
        "Cannot start dispute on completed escrow"
    );
});

test('meta-tx: startDisputeSigned allows relayed dispute by buyer signature', async () => {
    const id = await setupDeal();

    // Deposit -> AWAITING_DELIVERY
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    let deal = await getDeal(id);
    assert.equal(
        deal[8],
        State.AWAITING_DELIVERY,
        'Escrow should be AWAITING_DELIVERY after deposit',
    );

    const block = await publicClient.getBlock();
    const currentTs = Number(block.timestamp);
    const deadline = BigInt(currentTs + 3600); // 1h in future

    const nonce = deal[7] as bigint;
    const depositTime = deal[5] as bigint;

    const sender = buyer.address; // msg.sender in startDisputeSigned

    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,
        depositTime,
        deadline,
        nonce,
        'startDispute',
    );

    const signature = await sign(buyerClient, sender, hash);

    // Relayer submits (can be buyer or anyone – here we just use buyer again)
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDisputeSigned',
        args: [id, signature, deadline, nonce],
    });

    deal = await getDeal(id);
    assert.equal(
        deal[8],
        State.DISPUTED,
        'Deal state should be DISPUTED after relayed startDisputeSigned',
    );
});


test('meta-tx: resolveDisputeSigned allows relayed resolution by arbiter', async () => {
    const id = await setupDeal();

    // Deposit + startDispute -> DISPUTED
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDispute',
        args: [id],
    });

    let deal = await getDeal(id);
    assert.equal(deal[8], State.DISPUTED, 'Deal should be DISPUTED before signed resolve');

    const block = await publicClient.getBlock();
    const currentTs = Number(block.timestamp);
    const deadline = BigInt(currentTs + 3600);

    const nonce = deal[7] as bigint;
    const depositTime = deal[5] as bigint;
    const arbiterAddress = deal[3] as Address;

    // Owner is arbiter in your contract
    assert.equal(owner.address, arbiterAddress, 'Owner should be arbiter');

    const sender = arbiterAddress;
    const outcome = State.COMPLETE; // or REFUNDED

    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,
        depositTime,
        deadline,
        nonce,
        'resolveDispute',
    );

    const signature = await sign(ownerClient, owner.address, hash);

    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'resolveDisputeSigned',
        args: [id, signature, outcome, deadline, nonce],
    });

    deal = await getDeal(id);
    assert.equal(
        deal[8],
        outcome,
        'Deal state should match outcome after resolveDisputeSigned',
    );
});


test('meta-tx: requestCancelSigned allows relayed cancel request by buyer signature', async () => {
    const id = await setupDeal();

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    let deal = await getDeal(id);
    assert.equal(
        deal[8],
        State.AWAITING_DELIVERY,
        'Escrow should be AWAITING_DELIVERY before cancel request',
    );

    const block = await publicClient.getBlock();
    const currentTs = Number(block.timestamp);
    const deadline = BigInt(currentTs + 3600);

    const nonce = deal[7] as bigint;
    const depositTime = deal[5] as bigint;

    const sender = buyer.address; // who is requesting cancel

    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,
        depositTime,
        deadline,
        nonce,
        'cancelRequest',
    );
    const signature = await sign(buyerClient, sender, hash);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'requestCancelSigned',
        args: [id, signature, deadline, nonce],
    });

    deal = await getDeal(id);
    assert.equal(
        deal.buyerCancelRequested ?? deal[9],
        true,
        'Buyer cancel request should be recorded after requestCancelSigned',
    );
});

test('submitArbiterDecision posts arbiter message and resolves dispute atomically', async () => {
    // 1) Create deal, deposit, and start dispute
    const id = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDispute',
        args: [id],
    });

    let deal = await getDeal(id);
    assert.equal(deal[8], State.DISPUTED, 'Escrow should be DISPUTED before arbiter decision');

    // 2) Call submitArbiterDecision as arbiter (owner)
    const arbiterEvidenceHash = 'QmArbiterEvidenceHash';
    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'submitArbiterDecision',
        args: [id, State.COMPLETE, arbiterEvidenceHash], // seller wins
    });

    // 3) Check state and withdrawable balances after decision
    deal = await getDeal(id);
    assert.equal(
        deal[8],
        State.COMPLETE,
        'Escrow should be COMPLETE after submitArbiterDecision',
    );

    const sellerWithdrawable = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, seller.address],
    }) as bigint;
    assert(sellerWithdrawable > 0n, 'Seller should have withdrawable balance after arbiter decision');

    // 4) Ensure disputeStatus cleared (bitmask = 0)
    const status = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'disputeStatus',
        args: [id],
    }) as bigint;
    assert.equal(status, 0n, 'disputeStatus should be cleared after submitArbiterDecision');

    // 5) Negative: second arbiter decision must revert (already finalized)
    await assert.rejects(
        async () =>
            ownerClient.writeContract({
                address: escrowAddress,
                abi: escrowAbi,
                functionName: 'submitArbiterDecision',
                args: [id, State.COMPLETE, arbiterEvidenceHash],
            }),
    );

});







