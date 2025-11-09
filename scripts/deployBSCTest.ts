import * as dotenv from "dotenv";
dotenv.config();

import {
    createPublicClient,
    createWalletClient,
    http,
} from "viem";
import { bscTestnet } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";
import type { Address, Hex } from "viem";

// Load your contract artifacts dynamically:
function loadArtifact(path: string) {
    return JSON.parse(readFileSync(path, "utf8"));
}

// Replace with paths to your compiled contracts
const EscrowArtifact = loadArtifact("./artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json");
const USDTArtifact = loadArtifact("./artifacts/contracts/USDT.sol/USDT.json");

// === Load env variables ===
const BSCTESTNET_RPC_URL = process.env.BSCTESTNET_RPC_URL as string;
const BSCTESTNET_PRIVATE_KEY = process.env.BSCTESTNET_PRIVATE_KEY as `0x${string}`;
if (!BSCTESTNET_RPC_URL || !BSCTESTNET_PRIVATE_KEY) {
    throw new Error("Set BSCTESTNET_RPC_URL and BSCTESTNET_PRIVATE_KEY in environment");
}

// === Setup Viem clients for BSC Testnet ===
const publicClient = createPublicClient({
    chain: bscTestnet,
    transport: http(BSCTESTNET_RPC_URL),
});
const deployerAccount = privateKeyToAccount(BSCTESTNET_PRIVATE_KEY);
const deployerClient = createWalletClient({
    chain: bscTestnet,
    transport: http(BSCTESTNET_RPC_URL),
    account: deployerAccount,
});

// === Deploy helper ===
async function deployContract(
    walletClient: any,
    { abi, bytecode, args = [] }: { abi: any; bytecode: string; args?: any[] }
) {
    const hash = await walletClient.deployContract({
        abi,
        bytecode: bytecode as `0x${string}`,
        args,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    console.log("Deployed at block:", receipt.blockNumber);
    return { address: receipt.contractAddress as `0x${string}`, blockNumber: receipt.blockNumber };


}

async function main() {
    // Example: deploy USDT with constructor args for BSC Testnet
    const USDT_INITIAL_SUPPLY = 10_000_000n * 10n ** 6n; // 10 million tokens with 6 decimals
    const usdt = await deployContract(deployerClient, {
        abi: USDTArtifact.abi,
        bytecode: USDTArtifact.bytecode,
        args: ["Tether USD", "USDT", USDT_INITIAL_SUPPLY],
    });
    // console.log("USDT deployed at:", usdt.address);

    // Deploy Escrow contract with no constructor args
    const escrow = await deployContract(deployerClient, {
        abi: EscrowArtifact.abi,
        bytecode: EscrowArtifact.bytecode,
        args: ["0x337610d27c682E347C9cD60BD4b3b107C9d34dDd"]
    });
    console.log("PalindromeCryptoEscrow deployed at:", escrow.address, escrow.blockNumber);

    // Add further deployment or post-deployment logic as needed
}

main().catch((err) => {
    console.error("Deployment failed:", err);
    process.exit(1);
});
