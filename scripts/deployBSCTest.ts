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

// --- Load contract artifacts ---
function loadArtifact(path: string) {
    return JSON.parse(readFileSync(path, "utf8"));
}

const EscrowArtifact = loadArtifact("./artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json");
const USDTArtifact = loadArtifact("./artifacts/contracts/USDT.sol/USDT.json");

// === Load env variables ===
const BSCTESTNET_RPC_URL = process.env.BSCTESTNET_RPC_URL?.trim();
const BSCTESTNET_PRIVATE_KEY = process.env.OWNER_KEY?.trim();
const USDT_ADDRESS = process.env.USDT_ADDRESS?.trim();
const feeReceiver = process.env.FREE_RECEIVER?.trim()

if (!BSCTESTNET_RPC_URL || !BSCTESTNET_PRIVATE_KEY) {
    throw new Error("Set BSCTESTNET_RPC_URL and OWNER_KEY in environment");
}

function validateHexKey(key: string | undefined, label: string): `0x${string}` {
    if (!key) throw new Error(`Missing ${label}`);
    const stripped = key.replace(/^['"]|['"]$/g, '');
    if (!/^0x[0-9a-fA-F]{64}$/.test(stripped)) {
        throw new Error(`Invalid format for ${label}`);
    }
    return stripped as `0x${string}`;
}

const privateKey = validateHexKey(BSCTESTNET_PRIVATE_KEY, "OWNER_KEY");
const publicClient = createPublicClient({
    chain: bscTestnet,
    transport: http(BSCTESTNET_RPC_URL),
});
const deployerAccount = privateKeyToAccount(privateKey);
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
    return { address: receipt.contractAddress as `0x${string}`, blockNumber: receipt.blockNumber };
}

async function main() {
    // 1. Deploy USDT
    let usdtAddress = "";
    if (usdtAddress === "") {
        const USDT_INITIAL_SUPPLY = 10_000_000n * 10n ** 6n; // 10 million tokens with 6 decimals
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
}

main().catch((err) => {
    console.error("Deployment failed:", err);
    process.exit(1);
});
