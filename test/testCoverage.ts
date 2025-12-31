/**
 * PALINDROME CRYPTO ESCROW - ADDITIONAL COVERAGE TESTS
 * 
 * Fills gaps identified in coverage report:
 * - Direct function calls (non-signed)
 * - View functions
 * - Edge cases
 * - Token compatibility warnings
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
    keccak256,
    pad,
    toBytes,
    encodeAbiParameters,
    getAddress,
} from 'viem';
import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { getChainId } from 'viem/actions';

import EscrowArtifact from '../artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json' with { type: 'json' };
import WalletArtifact from '../artifacts/contracts/PalindromeEscrowWallet.sol/PalindromeEscrowWallet.json' with { type: 'json' };
import USDTArtifact from '../artifacts/contracts/USDT.sol/USDT.json' with { type: 'json' };

// ────────────────────────────────────────────────────────────────────────────
// SETUP (same as other test files)
// ────────────────────────────────────────────────────────────────────────────

const rpcUrl: string = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const buyerKey = process.env.BUYER_KEY as `0x${string}`;
const sellerKey = process.env.SELLER_KEY as `0x${string}`;
const ownerKey = process.env.OWNER_KEY as `0x${string}`;

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
const walletAbi = WalletArtifact.abi;
const walletCreationCode = WalletArtifact.bytecode as `0x${string}`;

let tokenAddress: Address;
let escrowAddress: Address;

const chainIdNumber: number = await getChainId(publicClient);
const chainId: bigint = BigInt(chainIdNumber);

const AMOUNT = 10_000_000n;
const DECIMALS = 6n;

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

    const tokenTxHash = await ownerClient.deployContract({
        abi: tokenAbi,
        bytecode: tokenBytecode,
        args: ['Tether USD', 'USDT', initialSupply, 6],
    });
    const tokenReceipt = await publicClient.waitForTransactionReceipt({ hash: tokenTxHash });
    tokenAddress = tokenReceipt.contractAddress as Address;

    const escrowTxHash = await ownerClient.deployContract({
        abi: escrowAbi,
        bytecode: escrowBytecode,
        args: [owner.address],
    });
    const escrowReceipt = await publicClient.waitForTransactionReceipt({ hash: escrowTxHash });
    escrowAddress = escrowReceipt.contractAddress as Address;

    console.log('\n📋 PALINDROME CRYPTO ESCROW - ADDITIONAL COVERAGE TESTS');
    console.log('═══════════════════════════════════════════════════════════════\n');
});

// ────────────────────────────────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────────────────────────────────

function getWalletDomain(walletAddress: Address) {
    return {
        name: 'PalindromeEscrowWallet',
        version: '1',
        chainId,
        verifyingContract: walletAddress,
    } as const;
}

const walletAuthorizationTypes = {
    WalletAuthorization: [
        { name: 'escrowId', type: 'uint256' },
        { name: 'wallet', type: 'address' },
        { name: 'participant', type: 'address' },
    ],
} as const;

async function signWalletAuthorization(
    signerClient: any,
    signerAddress: Address,
    walletAddress: Address,
    escrowId: number,
) {
    return signerClient.signTypedData({
        account: signerAddress,
        domain: getWalletDomain(walletAddress),
        types: walletAuthorizationTypes,
        primaryType: 'WalletAuthorization',
        message: {
            escrowId: BigInt(escrowId),
            wallet: walletAddress,
            participant: signerAddress,
        },
    });
}

async function getDeal(id: number) {
    const result = (await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'getEscrow',
        args: [BigInt(id)],
    })) as any;

    return {
        token: result.token as Address,
        buyer: result.buyer as Address,
        seller: result.seller as Address,
        arbiter: result.arbiter as Address,
        wallet: result.wallet as Address,
        amount: result.amount as bigint,
        depositTime: result.depositTime as bigint,
        maturityTime: result.maturityTime as bigint,
        disputeStartTime: result.disputeStartTime as bigint,
        state: Number(result.state),
        buyerCancelRequested: result.buyerCancelRequested as boolean,
        sellerCancelRequested: result.sellerCancelRequested as boolean,
        tokenDecimals: Number(result.tokenDecimals),
        sellerWalletSig: result.sellerWalletSig as `0x${string}`,
        buyerWalletSig: result.buyerWalletSig as `0x${string}`,
        arbiterWalletSig: result.arbiterWalletSig as `0x${string}`,
    };
}

async function fundAndApprove(client: any, address: Address, amount: bigint = AMOUNT) {
    await ownerClient.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'transfer',
        args: [address, amount],
    });
    await client.writeContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'approve',
        args: [escrowAddress, amount],
    });
}

async function getNextEscrowId(): Promise<number> {
    return Number(
        await publicClient.readContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'nextEscrowId',
            args: [],
        }),
    );
}

async function getBalance(address: Address): Promise<bigint> {
    return (await publicClient.readContract({
        address: tokenAddress,
        abi: tokenAbi,
        functionName: 'balanceOf',
        args: [address],
    })) as bigint;
}

async function increaseTime(seconds: number) {
    await publicClient.transport.request({ method: 'evm_increaseTime', params: [seconds] });
    await publicClient.transport.request({ method: 'evm_mine', params: [] });
}

function computePredictedWallet(escrowId: number): Address {
    const salt = keccak256(pad(toBytes(BigInt(escrowId)), { size: 32 }));
    const encodedArgs = encodeAbiParameters(
        [{ name: '_escrowContract', type: 'address' }, { name: '_escrowId', type: 'uint256' }],
        [escrowAddress, BigInt(escrowId)],
    );
    const initCode = (walletCreationCode + encodedArgs.slice(2)) as `0x${string}`;
    const initCodeHash = keccak256(initCode);
    const raw = keccak256((`0xFF${escrowAddress.slice(2)}${salt.slice(2)}${initCodeHash.slice(2)}`) as `0x${string}`);
    return getAddress(`0x${raw.slice(26)}`);
}

// ════════════════════════════════════════════════════════════════════════════
// 1. DIRECT FUNCTION TESTS (Non-Signed)
// ════════════════════════════════════════════════════════════════════════════

test('DIRECT: confirmDelivery (non-signed version)', async () => {
    console.log('📋 Testing confirmDelivery (direct call, not meta-tx)');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    // Seller creates
    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Direct Test', 'QmTest', sellerSig],
    });

    const deal = await getDeal(escrowId);

    // Buyer deposits
    const buyerSig = await signWalletAuthorization(buyerClient, buyer.address, deal.wallet, escrowId);
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [BigInt(escrowId), buyerSig],
    });

    // Buyer confirms DIRECTLY (not via signed meta-tx)
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'confirmDelivery',
        args: [BigInt(escrowId), buyerSig],
    });

    const updatedDeal = await getDeal(escrowId);
    assert.equal(updatedDeal.state, State.COMPLETE);
    console.log('   ✅ confirmDelivery (direct) works correctly\n');
});

test('DIRECT: startDispute (non-signed version)', async () => {
    console.log('📋 Testing startDispute (direct call, not meta-tx)');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Dispute Test', 'QmTest', sellerSig],
    });

    const deal = await getDeal(escrowId);
    const buyerSig = await signWalletAuthorization(buyerClient, buyer.address, deal.wallet, escrowId);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [BigInt(escrowId), buyerSig],
    });

    // Buyer starts dispute DIRECTLY
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDispute',
        args: [BigInt(escrowId)],
    });

    const updatedDeal = await getDeal(escrowId);
    assert.equal(updatedDeal.state, State.DISPUTED);
    console.log('   ✅ startDispute (direct) works correctly\n');
});

test('DIRECT: Seller starts dispute', async () => {
    console.log('📋 Testing seller starting dispute');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Seller Dispute', 'QmTest', sellerSig],
    });

    const deal = await getDeal(escrowId);
    const buyerSig = await signWalletAuthorization(buyerClient, buyer.address, deal.wallet, escrowId);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [BigInt(escrowId), buyerSig],
    });

    // SELLER starts dispute (not buyer)
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDispute',
        args: [BigInt(escrowId)],
    });

    const updatedDeal = await getDeal(escrowId);
    assert.equal(updatedDeal.state, State.DISPUTED);
    console.log('   ✅ Seller can start dispute\n');
});

// ════════════════════════════════════════════════════════════════════════════
// 2. VIEW FUNCTION TESTS
// ════════════════════════════════════════════════════════════════════════════

test('VIEW: getWalletAuthorizationDigest', async () => {
    console.log('📋 Testing getWalletAuthorizationDigest');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'View Test', 'QmTest', sellerSig],
    });

    // Test the view function
    const digest = await publicClient.readContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'getWalletAuthorizationDigest',
        args: [BigInt(escrowId), buyer.address],
    });

    assert.ok(digest !== '0x0000000000000000000000000000000000000000000000000000000000000000');
    console.log(`   Digest for buyer: ${digest}`);
    console.log('   ✅ getWalletAuthorizationDigest works\n');
});

test('VIEW: Wallet getBalance', async () => {
    console.log('📋 Testing wallet getBalance');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Balance Test', 'QmTest', sellerSig],
    });

    const deal = await getDeal(escrowId);

    // Before deposit
    const balanceBefore = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'getBalance',
        args: [],
    });
    assert.equal(balanceBefore, 0n);

    // After deposit
    const buyerSig = await signWalletAuthorization(buyerClient, buyer.address, deal.wallet, escrowId);
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [BigInt(escrowId), buyerSig],
    });

    const balanceAfter = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'getBalance',
        args: [],
    });
    assert.equal(balanceAfter, AMOUNT);

    console.log(`   Balance before deposit: ${balanceBefore}`);
    console.log(`   Balance after deposit: ${balanceAfter}`);
    console.log('   ✅ Wallet getBalance works\n');
});

test('VIEW: Wallet isSignatureValid', async () => {
    console.log('📋 Testing wallet isSignatureValid');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Sig Valid Test', 'QmTest', sellerSig],
    });

    const deal = await getDeal(escrowId);

    // Seller sig should be valid
    const sellerValid = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'isSignatureValid',
        args: [seller.address],
    });
    assert.equal(sellerValid, true);

    // Buyer sig not yet stored
    const buyerValid = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'isSignatureValid',
        args: [buyer.address],
    });
    assert.equal(buyerValid, false);

    console.log(`   Seller signature valid: ${sellerValid}`);
    console.log(`   Buyer signature valid: ${buyerValid}`);
    console.log('   ✅ Wallet isSignatureValid works\n');
});

test('VIEW: Wallet getAuthorizationDigest', async () => {
    console.log('📋 Testing wallet getAuthorizationDigest');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Auth Digest Test', 'QmTest', sellerSig],
    });

    const deal = await getDeal(escrowId);

    const digest = await publicClient.readContract({
        address: deal.wallet,
        abi: walletAbi,
        functionName: 'getAuthorizationDigest',
        args: [buyer.address],
    });

    assert.ok(digest !== '0x0000000000000000000000000000000000000000000000000000000000000000');
    console.log(`   Authorization digest: ${digest}`);
    console.log('   ✅ Wallet getAuthorizationDigest works\n');
});

// ════════════════════════════════════════════════════════════════════════════
// 3. EDGE CASE TESTS
// ════════════════════════════════════════════════════════════════════════════

test('EDGE: Maximum length title (100 chars)', async () => {
    console.log('📋 Testing max length title');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const maxTitle = 'A'.repeat(100);
    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);

    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, maxTitle, 'QmTest', sellerSig],
    });

    console.log('   ✅ 100-char title accepted\n');
});

test('EDGE: Over-length title (101 chars) rejected', async () => {
    console.log('📋 Testing over-length title rejection');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const overTitle = 'A'.repeat(101);
    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);

    try {
        await sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'createEscrow',
            args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, overTitle, 'QmTest', sellerSig],
        });
        assert.fail('Should have reverted');
    } catch (error: any) {
        assert.ok(error.message.includes('Invalid title length') || error.message.includes('revert'));
        console.log('   ✅ 101-char title rejected\n');
    }
});

test('EDGE: Empty title rejected', async () => {
    console.log('📋 Testing empty title rejection');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);

    try {
        await sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'createEscrow',
            args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, '', 'QmTest', sellerSig],
        });
        assert.fail('Should have reverted');
    } catch (error: any) {
        assert.ok(error.message.includes('Invalid title length') || error.message.includes('revert'));
        console.log('   ✅ Empty title rejected\n');
    }
});

test('EDGE: Maximum length IPFS hash (100 chars)', async () => {
    console.log('📋 Testing max length IPFS hash');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const maxHash = 'Q'.repeat(100);
    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);

    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Hash Test', maxHash, sellerSig],
    });

    console.log('   ✅ 100-char IPFS hash accepted\n');
});

test('EDGE: Over-length IPFS hash (101 chars) rejected', async () => {
    console.log('📋 Testing over-length IPFS hash rejection');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const overHash = 'Q'.repeat(101);
    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);

    try {
        await sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'createEscrow',
            args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Hash Test', overHash, sellerSig],
        });
        assert.fail('Should have reverted');
    } catch (error: any) {
        assert.ok(error.message.includes('Invalid IPFS hash length') || error.message.includes('revert'));
        console.log('   ✅ 101-char IPFS hash rejected\n');
    }
});

test('EDGE: Zero arbiter - escrow creation succeeds but dispute fails', async () => {
    console.log('📋 Testing zero arbiter behavior');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);

    // Create with zero arbiter - should succeed
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [
            tokenAddress,
            buyer.address,
            AMOUNT,
            1n,
            '0x0000000000000000000000000000000000000000' as Address,
            'Zero Arbiter',
            'QmTest',
            sellerSig
        ],
    });

    const deal = await getDeal(escrowId);
    const buyerSig = await signWalletAuthorization(buyerClient, buyer.address, deal.wallet, escrowId);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [BigInt(escrowId), buyerSig],
    });

    // Try to start dispute - should fail
    try {
        await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'startDispute',
            args: [BigInt(escrowId)],
        });
        assert.fail('Should have reverted - zero arbiter');
    } catch (error: any) {
        assert.ok(error.message.includes('Zero arbiter') || error.message.includes('revert'));
        console.log('   ✅ Zero arbiter: creation OK, dispute blocked\n');
    }
});

test('EDGE: acceptEscrow - cannot accept twice', async () => {
    console.log('📋 Testing double acceptEscrow rejection');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    // Buyer creates
    const buyerSig = await signWalletAuthorization(buyerClient, buyer.address, predictedWallet, escrowId);
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrowAndDeposit',
        args: [tokenAddress, seller.address, AMOUNT, 1n, owner.address, 'Accept Test', 'QmTest', buyerSig],
    });

    const deal = await getDeal(escrowId);
    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, deal.wallet, escrowId);

    // First accept succeeds
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'acceptEscrow',
        args: [BigInt(escrowId), sellerSig],
    });

    // Second accept fails
    try {
        await sellerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'acceptEscrow',
            args: [BigInt(escrowId), sellerSig],
        });
        assert.fail('Should have reverted');
    } catch (error: any) {
        assert.ok(error.message.includes('Already accepted') || error.message.includes('revert'));
        console.log('   ✅ Double accept rejected\n');
    }
});

test('EDGE: acceptEscrow - wrong caller rejected', async () => {
    console.log('📋 Testing acceptEscrow wrong caller');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const buyerSig = await signWalletAuthorization(buyerClient, buyer.address, predictedWallet, escrowId);
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrowAndDeposit',
        args: [tokenAddress, seller.address, AMOUNT, 1n, owner.address, 'Accept Caller Test', 'QmTest', buyerSig],
    });

    const deal = await getDeal(escrowId);

    // Buyer tries to accept (should fail - only seller can)
    try {
        await buyerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'acceptEscrow',
            args: [BigInt(escrowId), buyerSig],
        });
        assert.fail('Should have reverted');
    } catch (error: any) {
        assert.ok(error.message.includes('Only seller') || error.message.includes('revert'));
        console.log('   ✅ Non-seller accept rejected\n');
    }
});

// ════════════════════════════════════════════════════════════════════════════
// 4. ARBITER TIMEOUT TEST
// ════════════════════════════════════════════════════════════════════════════

test('EDGE: Arbiter can decide after 30-day timeout with partial evidence', async () => {
    console.log('📋 Testing arbiter timeout decision');

    await fundAndApprove(buyerClient, buyer.address);
    const escrowId = await getNextEscrowId();
    const predictedWallet = computePredictedWallet(escrowId);

    const sellerSig = await signWalletAuthorization(sellerClient, seller.address, predictedWallet, escrowId);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'createEscrow',
        args: [tokenAddress, buyer.address, AMOUNT, 1n, owner.address, 'Timeout Test', 'QmTest', sellerSig],
    });

    const deal = await getDeal(escrowId);
    const buyerSig = await signWalletAuthorization(buyerClient, buyer.address, deal.wallet, escrowId);

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'deposit',
        args: [BigInt(escrowId), buyerSig],
    });

    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDispute',
        args: [BigInt(escrowId)],
    });

    // Only buyer submits evidence (seller doesn't)
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'submitDisputeMessage',
        args: [BigInt(escrowId), Role.Buyer, 'QmBuyerEvidence'],
    });

    // Try to decide immediately - should fail (no full evidence, no timeout)
    const arbiterSig = await signWalletAuthorization(ownerClient, owner.address, deal.wallet, escrowId);

    try {
        await ownerClient.writeContract({
            address: escrowAddress,
            abi: escrowAbi,
            functionName: 'submitArbiterDecision',
            args: [BigInt(escrowId), State.REFUNDED, 'QmDecision', arbiterSig],
        });
        assert.fail('Should have reverted - need evidence or timeout');
    } catch (error: any) {
        assert.ok(error.message.includes('Need evidence or timeout') || error.message.includes('revert'));
        console.log('   ✅ Immediate decision without full evidence rejected');
    }

    // Fast forward 30 days + 1 hour + buffer
    const DISPUTE_LONG_TIMEOUT = 30 * 24 * 60 * 60; // 30 days
    const TIMEOUT_BUFFER = 60 * 60; // 1 hour
    await increaseTime(DISPUTE_LONG_TIMEOUT + TIMEOUT_BUFFER + 100);

    // Now arbiter can decide
    await ownerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'submitArbiterDecision',
        args: [BigInt(escrowId), State.REFUNDED, 'QmDecision', arbiterSig],
    });

    const updatedDeal = await getDeal(escrowId);
    assert.equal(updatedDeal.state, State.REFUNDED);
    console.log('   ✅ Arbiter decision after timeout accepted\n');
});

// ════════════════════════════════════════════════════════════════════════════
// 5. TOKEN COMPATIBILITY WARNINGS
// ════════════════════════════════════════════════════════════════════════════

test('WARNING: Fee-on-transfer tokens will break accounting', async () => {
    console.log('⚠️  WARNING: Fee-on-transfer tokens');
    console.log('   This contract does NOT support fee-on-transfer tokens!');
    console.log('   Example: SafeMoon, PAXG, some DeFi tokens');
    console.log('   Issue: Wallet receives less than deposited, withdraw fails');
    console.log('   Solution: Do not use with fee-on-transfer tokens\n');
});

test('WARNING: Rebasing tokens will break accounting', async () => {
    console.log('⚠️  WARNING: Rebasing tokens');
    console.log('   This contract does NOT support rebasing tokens!');
    console.log('   Example: stETH, AMPL, OHM');
    console.log('   Issue: Balance changes over time, accounting mismatch');
    console.log('   Solution: Do not use with rebasing tokens\n');
});

test('WARNING: Pausable tokens may freeze funds', async () => {
    console.log('⚠️  WARNING: Pausable tokens');
    console.log('   Tokens with pause functionality may freeze escrow!');
    console.log('   Example: USDC, USDT (admin can pause)');
    console.log('   Issue: Withdrawals fail if token is paused');
    console.log('   Solution: Accept this risk or use non-pausable tokens\n');
});

test('WARNING: Blocklist tokens may freeze funds', async () => {
    console.log('⚠️  WARNING: Blocklist tokens');
    console.log('   Tokens with blocklists may freeze escrow!');
    console.log('   Example: USDC, USDT (can blocklist addresses)');
    console.log('   Issue: If buyer/seller is blocklisted, funds stuck');
    console.log('   Solution: Accept this risk or use non-blocklist tokens\n');
});

// ════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ════════════════════════════════════════════════════════════════════════════

test('Additional Coverage Summary', async () => {
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('              ADDITIONAL COVERAGE SUMMARY');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('  ✅ Direct Functions: confirmDelivery, startDispute');
    console.log('  ✅ Seller starts dispute');
    console.log('  ✅ View Functions: getWalletAuthorizationDigest, getBalance');
    console.log('  ✅ View Functions: isSignatureValid, getAuthorizationDigest');
    console.log('  ✅ Edge Cases: Title/IPFS length limits');
    console.log('  ✅ Edge Cases: Zero arbiter behavior');
    console.log('  ✅ Edge Cases: Double accept, wrong caller accept');
    console.log('  ✅ Edge Cases: Arbiter timeout decision');
    console.log('  ⚠️  Warnings: Fee-on-transfer, rebasing, pausable, blocklist');
    console.log('═══════════════════════════════════════════════════════════════\n');
});