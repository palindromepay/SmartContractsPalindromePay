import * as dotenv from "dotenv";
dotenv.config();

import hre from "hardhat";
import {
    createPublicClient,
    createWalletClient,
    http,
    Chain,
} from "viem";
import { bscTestnet, baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";

// --- Load contract artifacts ---
function loadArtifact(path: string) {
    return JSON.parse(readFileSync(path, "utf8"));
}

const EscrowArtifact = loadArtifact("./artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json");
const USDTArtifact = loadArtifact("./artifacts/contracts/USDT.sol/USDT.json");

// === Load env variables ===
const BSCTESTNET_RPC_URL = process.env.BSCTESTNET_RPC_URL?.trim();
const BASE_SEPOLIA_RPC_URL = process.env.BASE_SEPOLIA_RPC_URL?.trim();
const PRIVATE_KEY = process.env.OWNER_KEY?.trim();
const feeReceiver = process.env.FREE_RECEIVER?.trim();

if (!BSCTESTNET_RPC_URL || !BASE_SEPOLIA_RPC_URL || !PRIVATE_KEY) {
    throw new Error("Set BSCTESTNET_RPC_URL, BASE_SEPOLIA_RPC_URL, and OWNER_KEY in environment");
}

function validateHexKey(key: string | undefined, label: string): `0x${string}` {
    if (!key) throw new Error(`Missing ${label}`);
    const stripped = key.replace(/^['"]|['"]$/g, '');
    if (!/^0x[0-9a-fA-F]{64}$/.test(stripped)) {
        throw new Error(`Invalid format for ${label}`);
    }
    return stripped as `0x${string}`;
}

const privateKey = validateHexKey(PRIVATE_KEY, "OWNER_KEY");
const deployerAccount = privateKeyToAccount(privateKey);

// === Create clients for each network ===
function createClients(chain: Chain, rpcUrl: string) {
    const publicClient = createPublicClient({
        chain,
        transport: http(rpcUrl),
    });
    const walletClient = createWalletClient({
        chain,
        transport: http(rpcUrl),
        account: deployerAccount,
    });
    return { publicClient, walletClient };
}

const bscClients = createClients(bscTestnet, BSCTESTNET_RPC_URL);
const baseClients = createClients(baseSepolia, BASE_SEPOLIA_RPC_URL);

// === Deploy helper ===
async function deployContract(
    publicClient: any,
    walletClient: any,
    { abi, bytecode, args = [] }: { abi: any; bytecode: string; args?: any[] }
) {
    const hash = await walletClient.deployContract({
        abi,
        bytecode: bytecode as `0x${string}`,
        args,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    return { address: receipt.contractAddress as `0x${string}`, blockNumber: receipt.blockNumber };
}

// === Deploy to a single network ===
async function deployToNetwork(
    networkName: string,
    publicClient: any,
    walletClient: any
): Promise<{ usdtAddress: string; escrowAddress: string; blockNumber: bigint }> {
    console.log(`\n========== Deploying to ${networkName} ==========\n`);

    const USDT_INITIAL_SUPPLY = 10_000_000n * 10n ** 6n;

    // Deploy USDT
    const usdt = await deployContract(publicClient, walletClient, {
        abi: USDTArtifact.abi,
        bytecode: USDTArtifact.bytecode,
        args: ["Tether USD", "USDT", USDT_INITIAL_SUPPLY, 6],
    });
    console.log(`[${networkName}] USDT deployed at:`, usdt.address);

    // Deploy Escrow
    const escrow = await deployContract(publicClient, walletClient, {
        abi: EscrowArtifact.abi,
        bytecode: EscrowArtifact.bytecode,
        args: [feeReceiver],
    });
    console.log(`[${networkName}] PalindromeCryptoEscrow deployed at:`, escrow.address);

    return {
        usdtAddress: usdt.address,
        escrowAddress: escrow.address,
        blockNumber: escrow.blockNumber,
    };
}

// === Verify contracts ===
async function verifyContracts(
    networkName: string,
    usdtAddress: string,
    escrowAddress: string
) {
    const USDT_INITIAL_SUPPLY = 10_000_000n * 10n ** 6n;

    console.log(`\n[${networkName}] Verifying contracts...`);

    // Verify USDT
    try {
        await (hre as any).run("verify:verify", {
            address: usdtAddress,
            constructorArguments: ["Tether USD", "USDT", USDT_INITIAL_SUPPLY, 6],
            network: networkName === "BSC Testnet" ? "bsctestnet" : "baseSepolia",
        });
        console.log(`[${networkName}] USDT verified successfully!`);
    } catch (error: any) {
        if (error.message.includes("Already Verified")) {
            console.log(`[${networkName}] USDT already verified.`);
        } else {
            console.error(`[${networkName}] USDT verification failed:`, error.message);
        }
    }

    // Verify Escrow
    try {
        await (hre as any).run("verify:verify", {
            address: escrowAddress,
            constructorArguments: [feeReceiver],
            network: networkName === "BSC Testnet" ? "bsctestnet" : "baseSepolia",
        });
        console.log(`[${networkName}] PalindromeCryptoEscrow verified successfully!`);
    } catch (error: any) {
        if (error.message.includes("Already Verified")) {
            console.log(`[${networkName}] PalindromeCryptoEscrow already verified.`);
        } else {
            console.error(`[${networkName}] PalindromeCryptoEscrow verification failed:`, error.message);
        }
    }
}

async function main() {
    console.log("Starting parallel deployment to BSC Testnet and Base Sepolia...\n");
    console.log("Deployer:", deployerAccount.address);
    console.log("Fee Receiver:", feeReceiver);

    // Deploy to both networks in parallel
    const [bscResult, baseResult] = await Promise.all([
        deployToNetwork("BSC Testnet", bscClients.publicClient, bscClients.walletClient),
        deployToNetwork("Base Sepolia", baseClients.publicClient, baseClients.walletClient),
    ]);

    // Wait for block explorers to index
    console.log("\nWaiting 30 seconds for block explorers to index...");
    await new Promise((resolve) => setTimeout(resolve, 30000));

    // Verify contracts on both networks in parallel
    await Promise.all([
        verifyContracts("BSC Testnet", bscResult.usdtAddress, bscResult.escrowAddress),
        verifyContracts("Base Sepolia", baseResult.usdtAddress, baseResult.escrowAddress),
    ]);

    // Final Summary
    console.log("\n");
    console.log("╔════════════════════════════════════════════════════════════════╗");
    console.log("║              PARALLEL DEPLOYMENT SUMMARY                       ║");
    console.log("╠════════════════════════════════════════════════════════════════╣");
    console.log("║  BSC TESTNET                                                   ║");
    console.log(`║  USDT: ${bscResult.usdtAddress}             ║`);
    console.log(`║  Escrow: ${bscResult.escrowAddress}           ║`);
    console.log("╠════════════════════════════════════════════════════════════════╣");
    console.log("║  BASE SEPOLIA                                                  ║");
    console.log(`║  USDT: ${baseResult.usdtAddress}             ║`);
    console.log(`║  Escrow: ${baseResult.escrowAddress}           ║`);
    console.log("╠════════════════════════════════════════════════════════════════╣");
    console.log(`║  Fee Receiver: ${feeReceiver}            ║`);
    console.log("╚════════════════════════════════════════════════════════════════╝");
}

main().catch((err) => {
    console.error("Deployment failed:", err);
    process.exit(1);
});
