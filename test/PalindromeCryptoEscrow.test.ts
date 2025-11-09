import 'dotenv/config'; // this runs dotenv automatically (Node 18+)
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { Address, createPublicClient, createWalletClient, encodePacked, http, keccak256, toHex, hexToBytes, WalletClient } from 'viem';
import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import EscrowServiceArtifact from '../artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json' with { type: "json" };
import USDTArtifact from '../artifacts/contracts/USDT.sol/USDT.json' with { type: "json" };

const rpcUrl = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const buyerKey = process.env.BUYER_KEY as `0x${string}`;
const sellerKey = process.env.SELLER_KEY as `0x${string}`;
const ownerKey = process.env.OWNER_KEY as `0x${string}`;

const publicClient = createPublicClient({ chain: foundry, transport: http(rpcUrl) });

const buyer = privateKeyToAccount(buyerKey);
const seller = privateKeyToAccount(sellerKey);
const owner = privateKeyToAccount(ownerKey);

const buyerClient = createWalletClient({ account: buyer, chain: foundry, transport: http(rpcUrl) });
const sellerClient = createWalletClient({ account: seller, chain: foundry, transport: http(rpcUrl) });
const ownerClient = createWalletClient({ account: owner, chain: foundry, transport: http(rpcUrl) });

const tokenAbi = USDTArtifact.abi;
const escrowAbi = EscrowServiceArtifact.abi;
const tokenBytecode = USDTArtifact.bytecode as `0x${string}`;
const escrowBytecode = EscrowServiceArtifact.bytecode as `0x${string}`;

let tokenAddress: `0x${string}`;
let escrowAddress: `0x${string}`;

const AMOUNT = 1_000_000n;

enum State { AWAITING_PAYMENT, AWAITING_DELIVERY, DISPUTED, COMPLETE, REFUNDED, CANCELED }

// ----- Deployment -----
before(async () => {
    const initialSupply = 1_000_000_000_000n;
    const tokenTxHash = await ownerClient.deployContract({
        abi: tokenAbi,
        bytecode: tokenBytecode,
        args: ["Tether USD", "USDT", initialSupply],
        account: owner.address,
        chain: foundry
    });
    tokenAddress = (await publicClient.waitForTransactionReceipt({ hash: tokenTxHash })).contractAddress as `0x${string}`;
    assert.ok(tokenAddress, 'Token deployment failed');

    const escrowTxHash = await ownerClient.deployContract({
        abi: escrowAbi,
        bytecode: escrowBytecode,
        args: [tokenAddress],
        account: owner.address,
        chain: foundry,
    });
    escrowAddress = (await publicClient.waitForTransactionReceipt({ hash: escrowTxHash })).contractAddress as `0x${string}`;
    assert.ok(escrowAddress, 'Escrow deployment failed');
});

// ----- Utility Functions -----
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
        chain: foundry,
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

// ----- Signature Helpers -----

function buildMessageHash(escrowAddress: Address, escrowId: number, participant: Address, depositTime: bigint, deadline: bigint, nonce: bigint, method: string) {
    return keccak256(
        encodePacked(
            ['address', 'uint256', 'address', 'uint256', 'uint256', 'uint256', 'string'],
            [escrowAddress, BigInt(escrowId), participant, depositTime, deadline, nonce, method]
        )
    );
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


// struct EscrowDeal {
//   address token;              // index 0
//   address buyer;              // 1
//   address seller;             // 2
//   address arbiter;            // 3
//   uint256 amount;             // 4
//   uint256 depositTime;        // 5
//   uint256 maturityTime;       // 6
//   State state;                // 7
//   bool buyerCancelRequested;  // 8
//   bool sellerCancelRequested; // 9
//   uint256 nonce;              // 10
// }

// ----- All Test Cases -----

test('deposit and delivery flow', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'confirmDelivery', args: [id] });
    const deal = await getDeal(id);
    assert.equal(deal[7], State.COMPLETE, 'State should be COMPLETE');

});


test('requestCancelSigned (buyer) executes via signature and deadline', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    let deal = await getDeal(id);
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = deal[10];

    const hash = buildMessageHash(escrowAddress, id, buyer.address, deal[5], deadline, nonce, 'cancelRequest');
    const signature = await sign(buyerClient, buyer.address, hash);

    // Buyer requests cancel (signed meta-tx, relayed by seller)
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'requestCancelSigned',
        args: [id, buyer.address, deadline, signature, nonce]
    });

    // State should still be AWAITING_DELIVERY == 1!
    deal = await getDeal(id);
    assert.equal(deal[7], State.AWAITING_DELIVERY, "State should still be AWAITING_DELIVERY after single cancel");

    // Seller also requests cancel (mutual cancel triggers cancellation)
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'requestCancel',
        args: [id]
    });

    deal = await getDeal(id);
    assert.equal(deal[7], State.CANCELED, "State should be CANCELED after both cancel");
});

test('startDisputeSigned from buyer works via signature', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    let deal = await getDeal(id);
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = deal[10];
    const hash = buildMessageHash(escrowAddress, id, buyer.address, deal[5], deadline, nonce, 'startDispute');
    const signature = await sign(buyerClient, buyer.address, hash);
    await sellerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'startDisputeSigned',
        args: [id, buyer.address, deadline, signature, nonce]
    });
    deal = await getDeal(id);
    assert.equal(deal[7], State.DISPUTED, "State should be DISPUTED");
});

test('refundSigned from arbiter works via signature', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    let deal = await getDeal(id);
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const nonce = deal[10];
    const hash = buildMessageHash(escrowAddress, id, owner.address, deal[5], deadline, nonce, 'refund');
    const signature = await sign(ownerClient, owner.address, hash);
    await buyerClient.writeContract({
        address: escrowAddress,
        abi: escrowAbi,
        functionName: 'refundSigned',
        args: [id, deadline, signature, nonce]
    });
    deal = await getDeal(id);
    assert.equal(deal[7], State.REFUNDED, "Should be refunded after signed refund by arbiter");
});

test('mutual cancel refunds buyer', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'requestCancel', args: [id] });
    await sellerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'requestCancel', args: [id] });
    const deal = await getDeal(id);
    assert.equal(deal[7], State.CANCELED);
});

test('dispute and resolve', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'startDispute', args: [id] });
    let deal = await getDeal(id);
    assert.equal(deal[7], State.DISPUTED);
    await ownerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'resolveDispute', args: [id, State.COMPLETE] });
    deal = await getDeal(id);
    assert.equal(deal[7], State.COMPLETE, 'State should be COMPLETE after arbiter resolves dispute');
});

test('reverts on double deposit', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await assert.rejects(
        async () => await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] }),
        'Second deposit should revert'
    );
});

test('reverts confirmDelivery before deposit', async () => {
    const id = await setupDeal();
    await assert.rejects(
        async () => await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'confirmDelivery', args: [id] }),
        'Confirm delivery before deposit should revert'
    );
});

test('reverts requestCancel before deposit', async () => {
    const id = await setupDeal();
    await assert.rejects(
        async () => await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'requestCancel', args: [id] }),
        'Request cancel before deposit should revert'
    );
});

test('cancelByTimeout refunds after timeout', async () => {
    const id = await setupDeal(AMOUNT, 14n);
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'requestCancel', args: [id] });
    await increaseTime(14 * 24 * 60 * 60 + 1);
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'cancelByTimeout', args: [id] });
    const deal = await getDeal(id);
    assert.equal(deal[7], State.CANCELED, "Escrow should be canceled after timeout refund");
});

test('cancelByTimeout reverts before timeout', async () => {
    const id = await setupDeal(AMOUNT, 1n);
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'requestCancel', args: [id] });
    await assert.rejects(
        async () => await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'cancelByTimeout', args: [id] }),
        "Should revert before timeout"
    );
});

test('autoRelease pays seller and completes after maturity', async () => {
    const id = await setupDeal(AMOUNT, 14n);
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await increaseTime(14 * 24 * 60 * 60 + 1);
    await ownerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'autoRelease', args: [id] });
    const deal = await getDeal(id);
    assert.equal(deal[7], State.COMPLETE, "Escrow should be marked complete after auto-release");
});

test('autoRelease reverts before timeout', async () => {
    const id = await setupDeal(AMOUNT, 14n);
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await assert.rejects(
        async () => await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'autoRelease', args: [id] }),
        "Auto-release should revert before maturity"
    );
});

test('submitDisputeMessage enforces per-role one message', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'startDispute', args: [id] });

    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'submitDisputeMessage', args: [id, 1, 'QM_BUYER_MSG'] });
    await assert.rejects(
        async () => await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'submitDisputeMessage', args: [id, 1, 'QM_BUYER_MSG2'] }),
        "Buyer double message should revert"
    );
    await sellerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'submitDisputeMessage', args: [id, 2, 'QM_SELLER_MSG'] });
    await ownerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'submitDisputeMessage', args: [id, 3, 'QM_ARBITER_MSG'] });
});

test('resolveDispute only by arbiter', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'startDispute', args: [id] });
    await assert.rejects(
        async () => await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'resolveDispute', args: [id, State.COMPLETE] }),
        "Buyer resolve should revert"
    );
});

test('refund reverts if not arbiter', async () => {
    const id = await setupDeal();
    await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'deposit', args: [id] });
    await assert.rejects(
        async () => await buyerClient.writeContract({ address: escrowAddress, abi: escrowAbi, functionName: 'refund', args: [id] }),
        "Refund by buyer should revert"
    );
});
