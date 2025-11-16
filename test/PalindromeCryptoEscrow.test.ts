/**
 * ===============================
 *   ESCROW CONTRACT TEST COVERAGE
 * ===============================
 * This test suite comprehensively covers the core and advanced business logic
 * of the PalindromeCryptoEscrow smart contract, including all critical payout scenarios 
 * for both the buyer, seller, and protocol fee recipient.
 * Covered Scenarios:
 *  - Buyer deposit and escrow funding flow
 *  - Delivery confirmation and seller withdrawal
 *  - Meta-transaction delivery (off-chain signature, relayed execution)
 *  - Protocol fee collection and owner fee withdrawal
 *  - Mutual cancel and cancelByTimeout logic, including buyer withdrawal
 *  - Dispute flow and both possible paths (COMPLETE to seller, REFUNDED to buyer)
 *  - Withdrawal logic for both buyer and seller
 *  - Double withdrawal attempts revert (no double-claim)
 *  - Withdrawal for zero-balance reverts (no empty pay)
 *  - Protocol fee double-withdrawal reverts
 *  - Role-based access enforcement for payout/withdraw paths
 *
 * (c) 2025 Palindrome Finance - QA Reference
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
    CANCELED: 5
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
        args: [tokenAddress, buyer.address, amount, maturityDays, "Escrow title", "QmHash"],
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


// Dispute resolved to seller, seller can withdraw
test('dispute resolved to seller and withdrawal', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'startDispute', args: [id] });


    // Arbitrator (owner) resolves to seller
    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'resolveDispute',
        args: [id, State.COMPLETE]
    });


    // Seller can withdraw
    let sellerWithdrawable = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, seller.address]
    });
    assert(Number(sellerWithdrawable) > 0, "Seller withdrawable after dispute resolution");


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
        args: [tokenAddress, seller.address]
    });
    assert.equal(Number(sellerWithdrawable), 0, "Withdrawable zero after seller claim");
});


// Dispute resolved to buyer, buyer can withdraw
test('dispute resolved to buyer and withdrawal', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'startDispute', args: [id] });


    // Arbitrator (owner) resolves to buyer (refund)
    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'resolveDispute',
        args: [id, State.REFUNDED]
    });


    // Buyer should have withdrawable
    let buyerWithdrawable = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, buyer.address]
    });
    assert(Number(buyerWithdrawable) > 0, "Buyer withdrawable after dispute resolved refunded");


    // Buyer withdraws
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdraw',
        args: [id]
    });
    buyerWithdrawable = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, buyer.address]
    });
    assert.equal(Number(buyerWithdrawable), 0, "Withdrawable zero after buyer claim");
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
        address: escrowAddress, abi: escrowAbi, functionName: 'withdrawAllFees', args: []
    });
    // LP is now zero; second withdraw fails
    await assert.rejects(
        async () => await ownerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'withdrawAllFees', args: [] }),
        "Second protocol fee withdrawal should revert"
    );
});


test('meta transaction delivery allows seller withdraw', async () => {
    /**
        [
        '0x5302E909d1e93e30F05B5D6Eea766363D14F9892', // 0: token
        '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC', // 1: buyer
        '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', // 2: seller
        '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', // 3: arbiter
        1000000n,                                     // 4: amount
        1763298728n,                                  // 5: depositTime
        0n,                                           // 6: maturityTime
        0n,                                           // 7: nonce
        1,                                            // 8: state
        false,                                        // 9: buyerCancelRequested
        false                                         // 10: sellerCancelRequested
        ]
     */
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });

    let deal = await getDeal(id);

    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = deal[7];           // nonce field in struct
    const depositTime = deal[5];     // depositTime in struct
    const sellerAddress = deal[2];   // seller address (hex string)

    const sender = buyer.address;

    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,         // msg.sender of confirmDeliverySigned
        depositTime,
        deadline,
        nonce,
        'confirmDelivery'
    );

    const signature = await sign(buyerClient, buyer.address, hash);

    // Buyer calls confirmDeliverySigned
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDeliverySigned',
        args: [id, signature, deadline, nonce]
    });

    // Now, seller should be able to withdraw
    let sellerWithdrawable = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'withdrawable',
        args: [tokenAddress, sellerAddress]
    });
    assert(Number(sellerWithdrawable) > 0, "Seller should have withdrawable after meta-confirm");

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
        args: [tokenAddress, sellerAddress]
    });
    console.log("Seller withdrawable balance:", sellerWithdrawable);
    assert.equal(Number(sellerWithdrawable), 0, "Seller withdrawable zero after claim");
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
        functionName: 'withdrawAllFees',
        args: []
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

test('meta transaction: signature replay is blocked by nonce', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    let deal = await getDeal(id);
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
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

    // First call works
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDeliverySigned',
        args: [id, signature, deadline, nonce]
    });

    // Second (replay) call fails as nonce is incremented
    await assert.rejects(
        async () => await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'confirmDeliverySigned',
            args: [id, signature, deadline, nonce]
        }),
        "Should revert on nonce replay"
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
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });

    let deal = await getDeal(id);

    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = deal[7];           // nonce field in struct
    const depositTime = deal[5];     // depositTime in struct

    const sender = buyer.address;

    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,         // msg.sender of confirmDeliverySigned
        depositTime,
        deadline,
        nonce,
        'startDispute'
    );

    const signature = await sign(buyerClient, sender, hash);

    // Relayer (could be anyone) submits
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDisputeSigned',
        args: [id, signature, deadline, nonce]
    });

    // Confirm state has changed to DISPUTED
    deal = await getDeal(id);
    assert.equal(deal[8], State.DISPUTED, "Deal state should be DISPUTED after relayed startDisputeSigned");
});

test('meta-tx: resolveDisputeSigned allows relayed resolution by arbiter', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'startDispute', args: [id] });

    let deal = await getDeal(id);

    /**
    [
    '0x5302E909d1e93e30F05B5D6Eea766363D14F9892', // 0: token
    '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC', // 1: buyer
    '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', // 2: seller
    '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', // 3: arbiter
    1000000n,                                     // 4: amount
    1763298728n,                                  // 5: depositTime
    0n,                                           // 6: maturityTime
    0n,                                           // 7: nonce
    1,                                            // 8: state
    false,                                        // 9: buyerCancelRequested
    false                                         // 10: sellerCancelRequested
    ]
    */
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = deal[7];           // nonce field in struct
    const depositTime = deal[5];     // depositTime in struct
    const arbiterAddress = deal[3]
    const ownerAddress = owner.address;

    const sender = arbiterAddress;

    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,         // msg.sender of confirmDeliverySigned
        depositTime,
        deadline,
        nonce,
        'resolveDispute'
    );

    console.log("deal[3] arbiter:", deal[3]);
    console.log("owner.address :", owner.address);
    // Should be exactly equal (case, prefix, etc.)
    assert.equal(owner.address, deal[3], "Owner should be arbiter in escrow");

    // decide outcome (e.g. State.COMPLETE for seller, or State.REFUNDED for buyer)
    const outcome = State.COMPLETE;

    const signature = await sign(ownerClient, ownerAddress, hash);

    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'resolveDisputeSigned',
        args: [id, signature, outcome, deadline, nonce]
    });

    // Confirm state
    deal = await getDeal(id);
    assert.equal(deal[8], outcome, "Deal state should match outcome after resolveDisputeSigned");
});

test('meta-tx: requestCancelSigned allows relayed cancel request by buyer signature', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });

    let deal = await getDeal(id);

    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = deal[7];         // nonce field
    const depositTime = deal[5];   // deposit time field

    // The relayer can be anyone; for the signature, use buyer's key/address
    const sender = buyer.address;

    // Your contract expects the hash to include chainId, contract address, escrowId, msg.sender (relayer),
    // depositTime, deadline, nonce, "cancelRequest"
    const hash = buildMessageHash(
        chainId,
        escrowAddress,
        id,
        sender,       // should be the relayer address, matches msg.sender in contract (here: buyer)
        depositTime,
        deadline,
        nonce,
        "cancelRequest"
    );
    const signature = await sign(buyerClient, sender, hash);

    // Relayer (may be buyer, seller, or any) submits the signed cancel request
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'requestCancelSigned',
        args: [id, signature, deadline, nonce],
    });
});





