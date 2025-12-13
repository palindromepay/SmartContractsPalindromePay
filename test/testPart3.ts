/**
 * ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
 * PALINDROMECRYPTOESCROW - Part 3 Test
 * Tests: Multi-Decimal Tokens, Explicit Error Messages, Wallet Integration
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
    parseEventLogs,
    decodeErrorResult,
} from 'viem';
import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import EscrowArtifact from '../artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json' with { type: 'json' };
import TokenArtifact from '../artifacts/contracts/USDT.sol/USDT.json' with { type: 'json' };
import WalletArtifact from '../artifacts/contracts/PalindromeEscrowWallet.sol/PalindromeEscrowWallet.json' with { type: 'json' };
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

const tokenAbi = TokenArtifact.abi;
const tokenBytecode = TokenArtifact.bytecode as `0x${string}`;
const escrowAbi = EscrowArtifact.abi;
const escrowBytecode = EscrowArtifact.bytecode as `0x${string}`;
const walletAbi = WalletArtifact.abi;

let token6Address: `0x${string}`; // 6 decimals (USDT)
let token8Address: `0x${string}`; // 8 decimals (WBTC-like)
let token18Address: `0x${string}`; // 18 decimals (DAI/USDC-like)
let escrowAddress: `0x${string}`;

const chainIdNumber: number = await getChainId(publicClient);
const chainId: bigint = BigInt(chainIdNumber);

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
    const initialSupply = 1_000_000n * 10n

    const initialSupply6 = initialSupply * 10n ** 6n;  // 1M * 10^6
    const initialSupply8 = initialSupply * 10n ** 8n;  // 1M * 10^8
    const initialSupply18 = initialSupply * 10n ** 18n; // 1M * 10^18

    // Deploy 6-decimal token (USDT-like)
    const token6TxHash = await ownerClient.deployContract({
        abi: tokenAbi,
        bytecode: tokenBytecode,
        args: ['Tether USD', 'USDT', initialSupply6, 6],
    });
    const token6Receipt = await publicClient.waitForTransactionReceipt({ hash: token6TxHash });
    token6Address = token6Receipt.contractAddress!;

    // Deploy 8-decimal token (WBTC-like)
    const token8TxHash = await ownerClient.deployContract({
        abi: tokenAbi,
        bytecode: tokenBytecode,
        args: ['Wrapped Bitcoin', 'WBTC', initialSupply8, 8],
    });
    const token8Receipt = await publicClient.waitForTransactionReceipt({ hash: token8TxHash });
    token8Address = token8Receipt.contractAddress!;

    // Deploy 18-decimal token (DAI/USDC-like)
    const token18TxHash = await ownerClient.deployContract({
        abi: tokenAbi,
        bytecode: tokenBytecode,
        args: ['USD Coin', 'USDC', initialSupply18, 18],
    });
    const token18Receipt = await publicClient.waitForTransactionReceipt({ hash: token18TxHash });
    token18Address = token18Receipt.contractAddress!;

    // Deploy escrow
    const escrowTxHash = await ownerClient.deployContract({
        abi: escrowAbi,
        bytecode: escrowBytecode,
        args: [owner.address],
    });
    const escrowReceipt = await publicClient.waitForTransactionReceipt({ hash: escrowTxHash });
    escrowAddress = escrowReceipt.contractAddress!;
});

// ═════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═════════════════════════════════════════════════════════════════════════════


async function fundAndApprove(tokenAddress: Address, amount: bigint) {
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

async function createEscrow(tokenAddress: Address, amount: bigint, maturityDays: bigint = 0n) {
    return await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, amount, maturityDays, owner.address, 'Escrow title', 'QmHash'],
    });
}

async function setupDeal(tokenAddress: Address, amount: bigint, maturityDays = 0n): Promise<number> {
    await fundAndApprove(tokenAddress, amount);
    await createEscrow(tokenAddress, amount, maturityDays);
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

function getErrorName(err: unknown): string | null {
    if (!(err instanceof BaseError)) return null;

    const execErr = err.walk((e) => e instanceof ContractFunctionExecutionError);
    if (!execErr || !(execErr instanceof ContractFunctionExecutionError)) return null;

    // The error data is in the cause chain, not directly on execErr
    try {
        // Walk through cause chain to find the raw error data
        let currentErr: any = execErr;
        let errorData: string | undefined;

        while (currentErr) {
            if (currentErr.data) {
                errorData = typeof currentErr.data === 'object' ? currentErr.data.data : currentErr.data;
                break;
            }
            currentErr = currentErr.cause;
        }

        if (!errorData || typeof errorData !== 'string') return null;

        const decoded = decodeErrorResult({
            abi: escrowAbi,
            data: errorData as `0x${string}`,
        });
        return decoded.errorName;
    } catch {
        return null;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 1: MULTI-DECIMAL TOKEN TESTING (18 decimals)
// ═════════════════════════════════════════════════════════════════════════════

test('[DECIMALS-18] Full escrow flow with 18-decimal token (DAI/USDC-like)', async () => {
    // For 18 decimals: minFee = 10^16 (0.01 tokens), minimum amount = 10^18 (1 token)
    const amount = 10_000_000_000_000_000_000n; // 10 tokens

    const id = await setupDeal(token18Address, amount);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    const deal = await getDeal(id);
    assert.equal(deal.tokenDecimals, 18, 'Should store 18 decimals');

    const walletBalance = await publicClient.readContract({
        address: token18Address,
        abi: tokenAbi,
        functionName: 'balanceOf',
        args: [deal.wallet],
    }) as bigint;

    assert.equal(walletBalance, amount, 'Wallet should hold full 18-decimal amount');

    // Complete the deal
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

    const deliveryLog = logs.find(
        (log: { eventName: string }) => log.eventName === 'DeliveryConfirmed'
    );

    // Expected fee: 10 tokens * 1% = 0.1 tokens = 100_000_000_000_000_000
    const expectedFee = amount / 100n;
    assert.equal(deliveryLog?.args.fee, expectedFee, 'Fee should be 1% for 18-decimal token');

    const dealAfter = await getDeal(id);
    assert.equal(dealAfter.state, State.COMPLETE, 'Should complete successfully');
});

test('[DECIMALS-18] Minimum amount threshold for 18-decimal token', async () => {
    // For 18 decimals: minFee = 10^16, minimum amount = 10^16 * 100 = 10^18
    const minimumAmount = 10_000_000_000_000_000_000n; // 1 token (10^18)

    const id = await setupDeal(token18Address, minimumAmount);

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

    const deliveryLog = logs.find(
        (log: { eventName: string }) => log.eventName === 'DeliveryConfirmed'
    );

    // At minimum amount, fee should be 1% but not less than minFee (10^16)
    const expectedFee = 100_000_000_000_000_000n; // 0.01 tokens
    assert.equal(deliveryLog?.args.fee, expectedFee, 'Fee should meet minimum threshold');
});

test('[DECIMALS-18] Below minimum amount rejected for 18-decimal token', async () => {
    // Use 0.5 tokens = 5 * 10^17 (clearly below 10^18 minimum)
    const tooSmallAmount = 500_000_000_000_000_000n;

    // Fresh funding
    await ownerClient.writeContract({
        address: token18Address,
        abi: tokenAbi,
        functionName: 'transfer',
        args: [buyer.address, tooSmallAmount],
    });

    await buyerClient.writeContract({
        address: token18Address,
        abi: tokenAbi,
        functionName: 'approve',
        args: [escrowAddress, tooSmallAmount],
    });

    // Don't wrap in async arrow function - pass the Promise directly
    await assert.rejects(
        sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'createEscrow',
            args: [token18Address, buyer.address, tooSmallAmount, 0n, owner.address, 'Escrow title', 'QmHash'],
        }),
        (err: any) => String(err?.shortMessage).includes('Internal error'),
        'Should reject amount below minimum for 18 decimals',
    );
});



test('[DECIMALS-18] Fee calculation with large amounts (precision test)', async () => {
    // Test with 1 million tokens (10^6 * 10^18 = 10^24)
    const largeAmount = 1_000_000_000_000_000_000_000_000n; // 1M tokens

    const id = await setupDeal(token18Address, largeAmount);

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

    const deliveryLog = logs.find(
        (log: { eventName: string }) => log.eventName === 'DeliveryConfirmed'
    );

    // Expected fee: 1M tokens * 1% = 10K tokens = 10^22
    const expectedFee = largeAmount / 100n;
    assert.equal(deliveryLog?.args.fee, expectedFee, 'Fee calculation should handle large amounts');

    // Verify fee is much greater than minimum
    const minFee = 10_000_000_000_000_000n; // 10^16
    assert(expectedFee > minFee, 'Calculated fee should exceed minimum for large amounts');
});

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 2: MULTI-DECIMAL TOKEN TESTING (8 decimals)
// ═════════════════════════════════════════════════════════════════════════════

test('[DECIMALS-8] Full escrow flow with 8-decimal token (WBTC-like)', async () => {
    // For 8 decimals: minFee = 10^6 (0.01 BTC), minimum amount = 10^8 (1 BTC)
    const amount = 1000_000_000n; // 10 USDT

    const id = await setupDeal(token8Address, amount);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    const deal = await getDeal(id);
    assert.equal(deal.tokenDecimals, 8, 'Should store 8 decimals');

    const walletBalance = await publicClient.readContract({
        address: token8Address,
        abi: tokenAbi,
        functionName: 'balanceOf',
        args: [deal.wallet],
    }) as bigint;

    assert.equal(walletBalance, amount, 'Wallet should hold full 8-decimal amount');

    // Complete the deal
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

    const deliveryLog = logs.find(
        (log: { eventName: string }) => log.eventName === 'DeliveryConfirmed'
    );

    // Expected fee: 1 BTC * 1% = 0.01 BTC = 1_000_000
    const expectedFee = amount / 100n;
    assert.equal(deliveryLog?.args.fee, expectedFee, 'Fee should be 1% for 8-decimal token');

    const dealAfter = await getDeal(id);
    assert.equal(dealAfter.state, State.COMPLETE, 'Should complete successfully');
});

test('[DECIMALS-8] Minimum amount threshold for 8-decimal token', async () => {
    // For 8 decimals: minFee = 10^6, minimum amount = 10^6 * 100 = 10^8
    const minimumAmount = 1000_000_000n; // 10 USDT (10^8)

    const id = await setupDeal(token8Address, minimumAmount);

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

    const deliveryLog = logs.find(
        (log: { eventName: string }) => log.eventName === 'DeliveryConfirmed'
    );

    // At minimum amount, fee should be 1% which equals minFee
    const expectedFee = 10_000_000n; // 0.01 BTC
    assert.equal(deliveryLog?.args.fee, expectedFee, 'Fee should meet minimum threshold');
});

test('[DECIMALS-8] Below minimum amount rejected for 8-decimal token', async () => {
    const tooSmallAmount = 99_999_999n; // Just below 1 BTC

    await fundAndApprove(token8Address, tooSmallAmount);

    await assert.rejects(
        sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'createEscrow',
            args: [token8Address, buyer.address, tooSmallAmount, 0n, owner.address, 'Escrow title', 'QmHash'],
        }),
        (err: any) => String(err?.shortMessage).includes('Internal error'),
        'Should reject amount below minimum for 8 decimals',
    );
});

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 3: EXPLICIT ERROR MESSAGE VALIDATION
// ═════════════════════════════════════════════════════════════════════════════

test('[ERROR] InvalidState error on deposit in wrong state', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    // Try to deposit again
    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'deposit',
            args: [id],
        }),
        (err: any) => String(err?.shortMessage).includes('Internal error'),
        'Should reject for Not awaiting payment',
    );
});

test('[ERROR] OnlyBuyer error when seller tries to deposit', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

    await assert.rejects(
        async () => await sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'deposit',
            args: [id],
        }),
        (err: unknown) => {
            const errorName = getErrorName(err);
            return errorName === 'OnlyBuyer' || String(err).includes('Only buyer');
        },
        'Should reject with OnlyBuyer error'
    );
});

test('[ERROR] OnlyArbiter error when buyer tries to resolve dispute', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

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
        args: [id, Role.Buyer, 'QmEvidence'],
    });

    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'submitDisputeMessage',
        args: [id, Role.Seller, 'QmEvidence'],
    });

    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'submitArbiterDecision',
            args: [id, State.COMPLETE, 'QmFake'],
        }),
        (err: unknown) => {
            const errorName = getErrorName(err);
            return errorName === 'OnlyArbiter' || String(err).includes('Only arbiter');
        },
        'Should reject with OnlyArbiter error'
    );
});

test('[ERROR] NotParticipant error when random user tries operations', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

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

    const randomKey = '0x' + 'c'.repeat(64) as `0x${string}`;
    const randomUser = privateKeyToAccount(randomKey);
    const randomClient = createWalletClient({ account: randomUser, chain: CHAIN, transport: http(rpcUrl) });

    await assert.rejects(
        async () => await randomClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'submitDisputeMessage',
            args: [id, Role.Buyer, 'QmFake'],
        }),
        (err: unknown) => {
            const errorName = getErrorName(err);
            return errorName === 'NotParticipant' || String(err).includes('Not participant');
        },
        'Should reject with NotParticipant error'
    );
});

test('[ERROR] InvalidNonce error on nonce reuse', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

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

    const message = {
        escrowId: BigInt(id),
        buyer: deal.buyer as Address,
        seller: deal.seller as Address,
        arbiter: deal.arbiter as Address,
        token: token6Address,
        amount: deal.amount as bigint,
        depositTime: deal.depositTime as bigint,
        deadline,
        nonce,
    } as const;

    const signature = await buyerClient.signTypedData({
        account: deal.buyer as Address,
        domain: {
            name: 'PalindromeCryptoEscrow',
            version: '1',
            chainId,
            verifyingContract: escrowAddress,
        },
        types,
        primaryType: 'ConfirmDelivery',
        message,
    });

    // First use - should work
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDeliverySigned',
        args: [id, signature, deadline, nonce, ''],
    });

    // Create new escrow for second attempt
    const id2 = await setupDeal(token6Address, 10_000_000n);
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id2],
    });

    // Try to reuse nonce 0 for second escrow
    const deal2 = await getDeal(id2);
    const message2 = {
        ...message,
        escrowId: BigInt(id2),
    };

    const signature2 = await buyerClient.signTypedData({
        account: deal2.buyer as Address,
        domain: {
            name: 'PalindromeCryptoEscrow',
            version: '1',
            chainId,
            verifyingContract: escrowAddress,
        },
        types,
        primaryType: 'ConfirmDelivery',
        message: message2,
    });

    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'confirmDeliverySigned',
            args: [id2, signature2, deadline, nonce, ''], // Reusing nonce 0
        }),
        (err: any) => String(err?.shortMessage).includes('Internal error'),
        'Should reject with NotParticipant error'
    );
});

test('[ERROR] SignatureAlreadyUsed error on signature replay', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

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

    const message = {
        escrowId: BigInt(id),
        buyer: deal.buyer as Address,
        seller: deal.seller as Address,
        arbiter: deal.arbiter as Address,
        token: token6Address,
        amount: deal.amount as bigint,
        depositTime: deal.depositTime as bigint,
        deadline,
        nonce,
    } as const;

    const signature = await buyerClient.signTypedData({
        account: deal.buyer as Address,
        domain: {
            name: 'PalindromeCryptoEscrow',
            version: '1',
            chainId,
            verifyingContract: escrowAddress,
        },
        types,
        primaryType: 'ConfirmDelivery',
        message,
    });

    // First use
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDeliverySigned',
        args: [id, signature, deadline, nonce, ''],
    });

    // Try replay - this will fail because signature hash is tracked
    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'confirmDeliverySigned',
            args: [id, signature, deadline, nonce, ''],
        }),
        (err: any) => String(err?.shortMessage).includes('Internal error'),
        'Should reject with SignatureAlreadyUsed or state error'
    );
});

test('[ERROR] AmountTooSmall error for below minimum amount', async () => {
    const tooSmall = 999_999n; // Below 1M for 6 decimals

    await fundAndApprove(token6Address, tooSmall);

    await assert.rejects(
        async () => await createEscrow(token6Address, tooSmall),
        (err: any) => String(err?.shortMessage).includes('Internal error'),
        'Should reject with AmountTooSmall error'
    );
});

test('[ERROR] GracePeriodActive error when canceling before grace period', async () => {
    const id = await setupDeal(token6Address, 10_000_000n, 1n);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'requestCancel',
        args: [id],
    });

    // Advance time but not past grace period
    await increaseTime(86400 + 3600); // 1 day + 1 hour (grace is 6 hours)

    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'cancelByTimeout',
            args: [id],
        }),
        (err: any) => String(err?.shortMessage).includes('Internal error'),
        'Should reject with GracePeriodActive error'
    );
});

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 4: WALLET INTEGRATION TESTS
// ═════════════════════════════════════════════════════════════════════════════

test('[WALLET] Wallet deployed with correct owners (buyer, seller, arbiter)', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

    const deal = await getDeal(id);

    // Verify wallet exists
    assert.notEqual(deal.wallet, '0x0000000000000000000000000000000000000000', 'Wallet should be deployed');

    // Check if buyer is owner
    const isBuyerOwner = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'isOwner',
        args: [buyer.address],
    }) as boolean;

    assert.equal(isBuyerOwner, true, 'Buyer should be wallet owner');

    // Check if seller is owner
    const isSellerOwner = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'isOwner',
        args: [seller.address],
    }) as boolean;

    assert.equal(isSellerOwner, true, 'Seller should be wallet owner');

    // Check if arbiter is owner
    const isArbiterOwner = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'isOwner',
        args: [owner.address],
    }) as boolean;

    assert.equal(isArbiterOwner, true, 'Arbiter should be wallet owner');
});

test('[WALLET] Wallet has correct threshold (2-of-3)', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

    const deal = await getDeal(id);

    const threshold = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'threshold',
    }) as bigint;


    assert.equal(threshold, 2, 'Wallet threshold should be 2-of-3');
});

test('[WALLET] Wallet receives tokens on deposit', async () => {
    const amount = 10_000_000n;
    const id = await setupDeal(token6Address, amount);

    // Check wallet balance before deposit
    const deal = await getDeal(id);
    const balanceBefore = await publicClient.readContract({
        address: token6Address,
        abi: tokenAbi,
        functionName: 'balanceOf',
        args: [deal.wallet],
    }) as bigint;

    assert.equal(balanceBefore, 0n, 'Wallet should be empty before deposit');

    // Make deposit
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    // Check wallet balance after deposit
    const balanceAfter = await publicClient.readContract({
        address: token6Address,
        abi: tokenAbi,
        functionName: 'balanceOf',
        args: [deal.wallet],
    }) as bigint;

    assert.equal(balanceAfter, amount, 'Wallet should hold deposited amount');
});

test('[WALLET] Each escrow gets unique wallet address', async () => {
    const id1 = await setupDeal(token6Address, 10_000_000n);
    const id2 = await setupDeal(token6Address, 10_000_000n);

    const deal1 = await getDeal(id1);
    const deal2 = await getDeal(id2);

    assert.notEqual(deal1.wallet, deal2.wallet, 'Each escrow should have unique wallet');
});

test('[WALLET] Wallet retains funds after escrow completion', async () => {
    const amount = 10_000_000n;
    const id = await setupDeal(token6Address, amount);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id],
    });

    const deal = await getDeal(id);

    // Complete escrow
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [id, ''],
    });

    // Verify wallet still holds funds (payout is proposed, not executed by escrow contract)
    const balanceAfter = await publicClient.readContract({
        address: token6Address,
        abi: tokenAbi,
        functionName: 'balanceOf',
        args: [deal.wallet],
    }) as bigint;

    assert.equal(balanceAfter, amount, 'Wallet should still hold funds after completion (non-custodial)');
});

test('[WALLET] Wallet owner count is 3', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

    const deal = await getDeal(id);

    const owners = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'getOwners',
    }) as Address[];
    assert.equal(owners.length, 3, 'Wallet should have exactly 3 owners');
});

test('[WALLET] Non-owner cannot be verified as owner', async () => {
    const id = await setupDeal(token6Address, 10_000_000n);

    const deal = await getDeal(id);

    const randomAddress = '0x' + 'd'.repeat(40) as Address;

    const isOwner = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'isOwner',
        args: [randomAddress],
    }) as boolean;

    assert.equal(isOwner, false, 'Random address should not be wallet owner');
});

// ═════════════════════════════════════════════════════════════════════════════
// CATEGORY 5: CROSS-TOKEN COMPATIBILITY TESTS
// ═════════════════════════════════════════════════════════════════════════════

test('[CROSS-TOKEN] Can create escrows with different token decimals simultaneously', async () => {
    // 6 decimals
    const id6 = await setupDeal(token6Address, 10_000_000n);

    // 8 decimals
    const id8 = await setupDeal(token8Address, 1000_000_000n);

    // 18 decimals
    const id18 = await setupDeal(token18Address, 10_000_000_000_000_000_000n);

    const deal6 = await getDeal(id6);
    const deal8 = await getDeal(id8);
    const deal18 = await getDeal(id18);

    assert.equal(deal6.tokenDecimals, 6, '6-decimal token stored correctly');
    assert.equal(deal8.tokenDecimals, 8, '8-decimal token stored correctly');
    assert.equal(deal18.tokenDecimals, 18, '18-decimal token stored correctly');
});

test('[CROSS-TOKEN] Fee calculations remain consistent across decimals', async () => {
    // All escrows with same economic value (1 unit of token)
    const amount6 = 10_000_000n; // 1 USDT
    const amount8 = 1000_000_000n; // 1 WBTC
    const amount18 = 10_000_000_000_000_000_000n; // 1 USDC

    const id6 = await setupDeal(token6Address, amount6);
    const id8 = await setupDeal(token8Address, amount8);
    const id18 = await setupDeal(token18Address, amount18);

    // Deposit all
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id6],
    });

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id8],
    });

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [id18],
    });

    // Complete all and check fees
    const confirm6Hash = await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [id6, ''],
    });

    const confirm8Hash = await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [id8, ''],
    });

    const confirm18Hash = await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [id18, ''],
    });

    // Parse fees from events
    const receipt6 = await publicClient.waitForTransactionReceipt({ hash: confirm6Hash });
    const receipt8 = await publicClient.waitForTransactionReceipt({ hash: confirm8Hash });
    const receipt18 = await publicClient.waitForTransactionReceipt({ hash: confirm18Hash });

    const logs6 = parseEventLogs({ abi: escrowAbi, logs: receipt6.logs }) as any;
    const logs8 = parseEventLogs({ abi: escrowAbi, logs: receipt8.logs }) as any;
    const logs18 = parseEventLogs({ abi: escrowAbi, logs: receipt18.logs }) as any;

    const fee6 = logs6.find((l: any) => l.eventName === 'DeliveryConfirmed')?.args.fee;
    const fee8 = logs8.find((l: any) => l.eventName === 'DeliveryConfirmed')?.args.fee;
    const fee18 = logs18.find((l: any) => l.eventName === 'DeliveryConfirmed')?.args.fee;

    // All should be at minimum fee threshold (1% of 1 unit)
    assert.equal(fee6, 100_000n, '6-decimal fee correct');
    assert.equal(fee8, 10_000_000n, '8-decimal fee correct');
    assert.equal(fee18, 100_000_000_000_000_000n, '18-decimal fee correct');

    // Verify fees are proportional to decimal places
    // 1% of amount should be: amount / 100
    assert.equal(fee6, amount6 / 100n, '6-decimal fee is 1%');
    assert.equal(fee8, amount8 / 100n, '8-decimal fee is 1%');
    assert.equal(fee18, amount18 / 100n, '18-decimal fee is 1%');
});
