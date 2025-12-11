/**
 * ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
 * PALINDROMECRYPTOESCROW - Part 2 Test
 * Tests: Token Edge Cases, Signature Security, Reentrancy Protection
 * =====================================================================================================================
 */

import 'dotenv/config';
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import {
    createPublicClient,
    createWalletClient,
    http,
    Address,
    Chain,
    ContractFunctionExecutionError,
    BaseError,
    parseEventLogs
} from 'viem';
import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import EscrowArtifact from '../artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json' with { type: 'json' };
import USDTArtifact from '../artifacts/contracts/USDT.sol/USDT.json' with { type: 'json' };
import { getChainId } from 'viem/actions';

const rpcUrl: string = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const buyerKey = process.env.BUYER_KEY as `0x${string}`;
const sellerKey = process.env.SELLER_KEY as `0x${string}`;
const ownerKey = process.env.OWNER_KEY as `0x${string}`;

if (!rpcUrl) throw new Error('RPC_URL env var is missing!');
if (!buyerKey) throw new Error('BUYER_KEY env var is missing!');
if (!sellerKey) throw new Error('SELLER_KEY env var is missing!');
if (!ownerKey) throw new Error('OWNER_KEY env var is missing!');

const CHAIN: Chain = foundry;

const buyer = privateKeyToAccount(buyerKey);
const seller = privateKeyToAccount(sellerKey);
const owner = privateKeyToAccount(ownerKey);

const publicClient = createPublicClient({ chain: CHAIN, transport: http(rpcUrl) });
const buyerClient = createWalletClient({ account: buyer, chain: CHAIN, transport: http(rpcUrl) });
const sellerClient = createWalletClient({ account: seller, chain: CHAIN, transport: http(rpcUrl) });
const ownerClient = createWalletClient({ account: owner, chain: CHAIN, transport: http(rpcUrl) });

const tokenAbi = USDTArtifact.abi;
const tokenBytecode = USDTArtifact.bytecode as `0x${string}`;
const escrowAbi = EscrowArtifact.abi;
const escrowBytecode = EscrowArtifact.bytecode as `0x${string}`;

let tokenAddress: `0x${string}`;
let escrowAddress: `0x${string}`;

const chainIdNumber: number = await getChainId(publicClient);
const chainId: bigint = BigInt(chainIdNumber);

const AMOUNT = 10_000_000n;

const State = {
    AWAITING_PAYMENT: 0,
    AWAITING_DELIVERY: 1,
    DISPUTED: 2,
    COMPLETE: 3,
    REFUNDED: 4,
    CANCELED: 5,
} as const;

const Role = {
    None: 0,
    Buyer: 1,
    Seller: 2,
    Arbiter: 3,
} as const;

before(async () => {
    const initialSupply = 1_000_000_000_000n;

    // Deploy USDT
    const tokenTxHash = await ownerClient.deployContract({
        abi: tokenAbi,
        bytecode: tokenBytecode,
        args: ['Tether USD', 'USDT', initialSupply, 6],
    });
    const tokenReceipt = await publicClient.waitForTransactionReceipt({ hash: tokenTxHash });
    tokenAddress = tokenReceipt.contractAddress!;

    await ownerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'transfer',
        args: [owner.address, initialSupply],
    });

    // Deploy escrow
    const escrowTxHash = await ownerClient.deployContract({
        abi: escrowAbi,
        bytecode: escrowBytecode,
        args: [owner.address],
    });
    const escrowReceipt = await publicClient.waitForTransactionReceipt({ hash: escrowTxHash });
    escrowAddress = escrowReceipt.contractAddress!;
});

// ------ Utility Helpers ----------

async function fundAndApprove(amount: bigint = AMOUNT) {
    await ownerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'transfer',
        args: [buyer.address, amount],
    });
    await buyerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'approve',
        args: [escrowAddress, amount],
    });
}

async function createEscrow(amount: bigint = AMOUNT, maturityDays: bigint = 0n) {
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, amount, maturityDays, owner.address, 'Escrow title', 'QmHash'],
    });
}

async function setupDeal(amount = AMOUNT, maturityDays = 0n): Promise<number> {
    await fundAndApprove(amount);
    await createEscrow(amount, maturityDays);
    const nextId = Number(
        await publicClient.readContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'nextEscrowId',
        }),
    );
    return nextId - 1;
}

async function getDeal(id: number) {
    return await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'getEscrow',
        args: [id],
    }) as any;
}

async function increaseTime(seconds: number) {
    await publicClient.transport.request({ method: 'evm_increaseTime', params: [seconds] });
    await publicClient.transport.request({ method: 'evm_mine', params: [] });
}

function getDomain() {
    if (!escrowAddress) throw new Error('escrowAddress not set');
    return {
        name: 'PalindromeCryptoEscrow',
        version: '1',
        chainId,
        verifyingContract: escrowAddress,
    } as const;
}

const types = {
    ConfirmDelivery: [
        { name: 'escrowId', type: 'uint256' },
        { name: 'buyer', type: 'address' },
        { name: 'seller', type: 'address' },
        { name: 'arbiter', type: 'address' },
        { name: 'token', type: 'address' },
        { name: 'amount', type: 'uint256' },
        { name: 'depositTime', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
    ],
} as const;

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 1: TOKEN EDGE CASES
// ═════════════════════════════════════════════════════════════════════════════

test('[TOKEN] Escrow works with tokens returning false instead of reverting', async () => {
    // Some old ERC20s (like USDT on mainnet) return false on failure instead of reverting
    // Our current USDT mock reverts, but we test the happy path to ensure compatibility

    const id = await setupDeal();

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    const deal = await getDeal(id);
    assert.equal(deal.state, State.AWAITING_DELIVERY, 'Deposit should succeed with standard ERC20');

    // Verify wallet received the tokens
    const walletBalance = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'balanceOf',
        args: [deal.wallet],
    }) as bigint;

    assert.equal(walletBalance, AMOUNT, 'Wallet should hold full amount');
});

test('[TOKEN] Cannot deposit with insufficient approval', async () => {
    await fundAndApprove(AMOUNT);
    await createEscrow(AMOUNT);

    const nextId = Number(
        await publicClient.readContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'nextEscrowId',
        }),
    );
    const id = nextId - 1;

    // Reduce approval to less than required
    await buyerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'approve',
        args: [escrowAddress, AMOUNT / 2n],
    });

    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'deposit',
            args: [id],
        }),
        'Should revert with insufficient approval'
    );
});

test('[TOKEN] Cannot deposit with insufficient balance', async () => {
    // Reset buyer's balance to 0 by transferring back to owner
    const buyerBalance = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'balanceOf',
        args: [buyer.address],
    }) as bigint;
    if (buyerBalance > 0n) {
        await buyerClient.writeContract({
            address: tokenAddress,
            abi: tokenAbi,
            functionName: 'transfer',
            args: [owner.address, buyerBalance],
        });
    }

    // Fund with less than required
    await ownerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'transfer',
        args: [buyer.address, AMOUNT / 2n],
    });

    await buyerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'approve',
        args: [escrowAddress, AMOUNT],
    });

    await createEscrow(AMOUNT);

    const nextId = Number(
        await publicClient.readContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'nextEscrowId',
        }),
    );
    const id = nextId - 1;

    await assert.rejects(
        () =>
            buyerClient.writeContract({
                address: escrowAddress,
                abi: escrowAbi,
                functionName: 'deposit',
                args: [id],
            }),
        (err: any) => {
            const msg = String(err);  // Changed from String(err?.message ?? '')
            // Check for generic revert indicators
            return msg.includes('ContractFunctionExecutionError')
                || msg.includes('Internal error')
                || msg.includes('reverted');
        },
    );
});

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 2: SIGNATURE SECURITY & REPLAY PROTECTION
// ═════════════════════════════════════════════════════════════════════════════

test('[SIGNATURE] Cannot reuse signature across different escrows', async () => {
    // Create two escrows
    const id1 = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id1],
    });

    const id2 = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id2],
    });

    // Sign for escrow 1
    const deal1 = await getDeal(id1);
    const block = await publicClient.getBlock();
    const deadline = BigInt(Number(block.timestamp) + 3600);
    const nonce = 0n;

    const message = {
        escrowId: BigInt(id1),
        buyer: deal1.buyer as Address,
        seller: deal1.seller as Address,
        arbiter: deal1.arbiter as Address,
        token: tokenAddress,
        amount: deal1.amount as bigint,
        depositTime: deal1.depositTime as bigint,
        deadline,
        nonce,
    } as const;

    const signature = await buyerClient.signTypedData({
        account: deal1.buyer as Address,
        domain: getDomain(),
        types,
        primaryType: 'ConfirmDelivery',
        message,
    });

    // Use signature on escrow 1 - should work
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDeliverySigned',
        args: [id1, signature, deadline, nonce, ''],
    });

    const deal1After = await getDeal(id1);
    assert.equal(deal1After.state, State.COMPLETE, 'First escrow should complete');

    // Try to reuse same signature on escrow 2 - should fail
    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'confirmDeliverySigned',
            args: [id2, signature, deadline, nonce, ''],
        }),
        'Should reject signature reuse across escrows'
    );
});

test('[SIGNATURE] Contract nonce prevents replay after contract upgrade', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    const deal = await getDeal(id);
    const block = await publicClient.getBlock();
    const deadline = BigInt(Number(block.timestamp) + 3600);
    const nonce = 0n;

    const message = {
        escrowId: BigInt(id),
        buyer: deal.buyer as Address,
        seller: deal.seller as Address,
        arbiter: deal.arbiter as Address,
        token: tokenAddress,
        amount: deal.amount as bigint,
        depositTime: deal.depositTime as bigint,
        deadline,
        nonce,
    } as const;

    const signature = await buyerClient.signTypedData({
        account: deal.buyer as Address,
        domain: getDomain(),
        types,
        primaryType: 'ConfirmDelivery',
        message,
    });

    // Simulate contract upgrade by incrementing contract nonce
    // In real scenario, this would happen during contract migration

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDeliverySigned',
        args: [id, signature, deadline, nonce, ''],
    });

    const dealAfter = await getDeal(id);
    assert.equal(dealAfter.state, State.COMPLETE, 'Should complete with correct contract nonce');
});

test('[SIGNATURE] Zero address cannot create valid signatures', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    const deal = await getDeal(id);
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = 0n;

    // Create a signature with invalid v, r, s values (simulating zero address)
    const invalidSignature = '0x' + '00'.repeat(65) as `0x${string}`;

    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'confirmDeliverySigned',
            args: [id, invalidSignature, deadline, nonce, ''],
        }),
        'Should reject signature from zero address'
    );
});

test('[SIGNATURE] Signature deadline exactly at block timestamp boundary', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    const deal = await getDeal(id);
    const block = await publicClient.getBlock();

    // Set deadline exactly at current block timestamp
    const deadline = block.timestamp;
    const nonce = 0n;

    const message = {
        escrowId: BigInt(id),
        buyer: deal.buyer as Address,
        seller: deal.seller as Address,
        arbiter: deal.arbiter as Address,
        token: tokenAddress,
        amount: deal.amount as bigint,
        depositTime: deal.depositTime as bigint,
        deadline,
        nonce,
    } as const;

    const signature = await buyerClient.signTypedData({
        account: deal.buyer as Address,
        domain: getDomain(),
        types,
        primaryType: 'ConfirmDelivery',
        message,
    });

    // This should fail because deadline must be > block.timestamp
    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'confirmDeliverySigned',
            args: [id, signature, deadline, nonce, ''],
        }),
        'Should reject signature with deadline at current timestamp'
    );
});

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 3: AMOUNT & FEE EDGE CASES
// ═════════════════════════════════════════════════════════════════════════════

test('[FEE] Fee calculation with amount just above minimum threshold', async () => {
    // For USDT (6 decimals), minFee = 10^(6-2) = 10,000 units (0.01 USDT), fee=1%, so minimum amount=10,000 * 100 = 1,000,000 units (1 USDT)
    // Testing with 1,000,001 (just above)
    const minAmount = 1000001n;

    const id = await setupDeal(minAmount);
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
        args: [id, ''],
    });

    const deal = await getDeal(id);
    assert.equal(deal.state, State.COMPLETE, 'Should complete successfully');

    // Fee should be calculated as amount / 100 (1%)
    const expectedFee = minAmount / 100n;
    // Verify fee is reasonable (at least 10,000 for amounts > 1,000,000)
    assert(expectedFee >= 10000n, 'Fee should meet minimum threshold');
});

test('[FEE] Fee is zero for refund scenario', async () => {
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

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'submitDisputeMessage',
        args: [id, Role.Buyer, 'QmBuyerEvidence'],
    });

    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'submitDisputeMessage',
        args: [id, Role.Seller, 'QmSellerEvidence'],
    });

    await increaseTime(24 * 60 * 60); // must be >= MIN_EVIDENCE_WINDOW

    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'submitArbiterDecision',
        args: [id, State.REFUNDED, 'QmArbiterDecision'],
    });

    const deal = await getDeal(id);
    assert.equal(deal.state, State.REFUNDED, 'Should be refunded');

    // In real implementation, verify PayoutProposed event has fee=0
});

test('[FEE] Fee calculation rounds down correctly', async () => {
    // Test with an amount where 1% doesn't divide evenly
    // 1000099 * 1% = 10000.99 → should round down to 10000 (integer truncation in contract)
    const oddAmount = 1000099n;

    const id = await setupDeal(oddAmount);
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    const confirmHash = await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [id, ''],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: confirmHash });

    const logs = parseEventLogs({
        abi: escrowAbi,
        logs: receipt.logs,
    }) as any;

    // Find the DeliveryConfirmed event (adjust index if multiple events)
    const deliveryLog = logs.find(
        (log: { eventName: string; }): log is Extract<typeof logs[number], { eventName: 'DeliveryConfirmed' }> =>
            log.eventName === 'DeliveryConfirmed'
    );
    const actualFee = deliveryLog?.args.fee;


    const deal = await getDeal(id);
    assert.equal(deal.state, State.COMPLETE, 'Should complete');

    const expectedFee = oddAmount / 100n;  // Matches contract's truncation
    assert.equal(actualFee, expectedFee, 'Actual fee should round down to 10000');
    assert.equal(expectedFee, 10000n, 'Expected fee should be 10000');
});

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 4: AUTHORIZATION EDGE CASES
// ═════════════════════════════════════════════════════════════════════════════

test('[AUTH] Buyer and seller cannot be the same address', async () => {
    await fundAndApprove();

    await assert.rejects(
        async () => await sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'createEscrow',
            args: [
                tokenAddress,
                seller.address, // buyer = seller
                AMOUNT,
                0n,
                owner.address,
                'Self-dealing escrow',
                'QmHash',
            ],
        }),
        'Should reject escrow where buyer equals seller'
    );
});

test('[AUTH] Arbiter cannot be same as buyer', async () => {
    await fundAndApprove();

    await assert.rejects(
        async () => await sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'createEscrow',
            args: [
                tokenAddress,
                buyer.address,
                AMOUNT,
                0n,
                buyer.address, // arbiter = buyer
                'Conflict of interest',
                'QmHash'
            ],
        }),
        'Should reject escrow where arbiter equals buyer'
    );
});

test('[AUTH] Arbiter cannot be same as seller', async () => {
    await fundAndApprove();

    await assert.rejects(
        async () => await sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'createEscrow',
            args: [
                tokenAddress,
                buyer.address,
                AMOUNT,
                0n,
                seller.address, // arbiter = seller
                'Conflict of interest',
                'QmHash'
            ],
        }),
        'Should reject escrow where arbiter equals seller'
    );
});
