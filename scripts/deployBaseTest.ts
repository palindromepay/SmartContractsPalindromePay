import * as dotenv from "dotenv";
dotenv.config();

import hre from "hardhat";
import {
    createPublicClient,
    createWalletClient,
    http,
} from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";

// --- Load contract artifacts ---
function loadArtifact(path: string) {
    return JSON.parse(readFileSync(path, "utf8"));
}

const EscrowArtifact = loadArtifact("./artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json");
const USDTArtifact = loadArtifact("./artifacts/contracts/USDT.sol/USDT.json");

// === Load env variables ===
const BASE_SEPOLIA_RPC_URL = process.env.BASE_SEPOLIA_RPC_URL?.trim();
const PRIVATE_KEY = process.env.OWNER_KEY?.trim();
const feeReceiver = process.env.FREE_RECEIVER?.trim();

if (!BASE_SEPOLIA_RPC_URL || !PRIVATE_KEY) {
    throw new Error("Set BASE_SEPOLIA_RPC_URL and OWNER_KEY in environment");
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
const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(BASE_SEPOLIA_RPC_URL),
});
const deployerAccount = privateKeyToAccount(privateKey);
const deployerClient = createWalletClient({
    chain: baseSepolia,
    transport: http(BASE_SEPOLIA_RPC_URL),
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
    return { address: receipt.contractAddress as `0x${string}`, blockNumber: receipt.blockNumber };
}

async function main() {
    console.log("\n========== Deploying to Base Sepolia ==========\n");

    const USDT_INITIAL_SUPPLY = 10_000_000n * 10n ** 6n; // 10 million tokens with 6 decimals

    // 1. Deploy USDT
    let usdtAddress = "";
    if (usdtAddress === "") {
        const usdt = await deployContract(deployerClient, {
            abi: USDTArtifact.abi,
            bytecode: USDTArtifact.bytecode,
            args: ["Tether USD", "USDT", USDT_INITIAL_SUPPLY, 6],
        });
        usdtAddress = usdt.address;
    } else {
        console.log("Using existing USDT at:", usdtAddress);
    }

    const escrow = await deployContract(deployerClient, {
        abi: EscrowArtifact.abi,
        bytecode: EscrowArtifact.bytecode,
        args: [feeReceiver],
    });
    const escrowAddress = escrow.address;

    console.log("USDT deployed at:", usdtAddress);
    console.log("PalindromeCryptoEscrow deployed at:", escrowAddress, escrow.blockNumber);

    // Wait for block explorer to index the contracts
    console.log("\nWaiting 30 seconds for block explorer to index...");
    await new Promise((resolve) => setTimeout(resolve, 30000));

    // Verify USDT
    console.log("\nVerifying USDT...");
    try {
        await (hre as any).run("verify:verify", {
            address: usdtAddress,
            constructorArguments: ["Tether USD", "USDT", USDT_INITIAL_SUPPLY, 6],
        });
        console.log("USDT verified successfully!");
    } catch (error: any) {
        if (error.message.includes("Already Verified")) {
            console.log("USDT already verified.");
        } else {
            console.error("USDT verification failed:", error.message);
        }
    }

    // Verify PalindromeCryptoEscrow
    console.log("\nVerifying PalindromeCryptoEscrow...");
    try {
        await (hre as any).run("verify:verify", {
            address: escrowAddress,
            constructorArguments: [feeReceiver],
        });
        console.log("PalindromeCryptoEscrow verified successfully!");
    } catch (error: any) {
        if (error.message.includes("Already Verified")) {
            console.log("PalindromeCryptoEscrow already verified.");
        } else {
            console.error("PalindromeCryptoEscrow verification failed:", error.message);
        }
    }

    // Summary
    console.log("\n========== Base Sepolia Deployment Summary ==========");
    console.log("USDT:", usdtAddress);
    console.log("PalindromeCryptoEscrow:", escrowAddress);
    console.log("Fee Receiver:", feeReceiver);
    console.log("=====================================================");
}

main().catch((err) => {
    console.error("Base Sepolia deployment failed:", err);
    process.exit(1);
});
