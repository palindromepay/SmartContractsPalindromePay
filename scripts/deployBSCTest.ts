import * as dotenv from "dotenv";
dotenv.config();

import {
    createPublicClient,
    createWalletClient,
    http,
    encodeFunctionData,
} from "viem";
import { bscTestnet } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";

// --- Load contract artifacts ---
function loadArtifact(path: string) {
    return JSON.parse(readFileSync(path, "utf8"));
}

const EscrowArtifact = loadArtifact("./artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json");
const LPArtifact = loadArtifact("./artifacts/contracts/PalindromeEscrowLP.sol/PalindromeEscrowLP.json");
const USDTArtifact = loadArtifact("./artifacts/contracts/USDT.sol/USDT.json");

// === Load env variables ===
const BSCTESTNET_RPC_URL = process.env.BSCTESTNET_RPC_URL?.trim();
const BSCTESTNET_PRIVATE_KEY = process.env.OWNER_KEY?.trim();
const USDT_ADDRESS = process.env.USDT_ADDRESS?.trim();

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
    console.log("Deployed at block:", receipt.blockNumber, "Address:", receipt.contractAddress);
    return { address: receipt.contractAddress as `0x${string}`, blockNumber: receipt.blockNumber };
}

async function main() {
    // 1. Deploy USDT
    let usdtAddress = USDT_ADDRESS;
    if (!usdtAddress) {
        const USDT_INITIAL_SUPPLY = 10_000_000n * 10n ** 6n; // 10 million tokens with 6 decimals
        const usdt = await deployContract(deployerClient, {
            abi: USDTArtifact.abi,
            bytecode: USDTArtifact.bytecode,
            args: ["Tether USD", "USDT", USDT_INITIAL_SUPPLY],
        });
        usdtAddress = usdt.address;
        console.log("USDT deployed at:", usdtAddress);
    } else {
        console.log("Using existing USDT at:", usdtAddress);
    }

    // 2. Deploy LP token
    const lp = await deployContract(deployerClient, {
        abi: LPArtifact.abi,
        bytecode: LPArtifact.bytecode,
        args: [],
    });
    const lpAddress = lp.address;
    console.log("LP Token deployed at:", lpAddress);

    // 3. Deploy Escrow contract - pass LP address and USDT address
    const escrow = await deployContract(deployerClient, {
        abi: EscrowArtifact.abi,
        bytecode: EscrowArtifact.bytecode,
        args: [lpAddress, usdtAddress],
    });
    const escrowAddress = escrow.address;
    console.log("PalindromeCryptoEscrow deployed at:", escrowAddress, escrow.blockNumber);

    // 4. Set LP minter to escrow contract
    const calldata = encodeFunctionData({
        abi: LPArtifact.abi,
        functionName: "setMinter",
        args: [escrowAddress]
    });
    const txHash = await deployerClient.sendTransaction({
        to: lpAddress,
        data: calldata,
    });
    await publicClient.waitForTransactionReceipt({ hash: txHash });
    console.log("LP minter set to escrow:", escrowAddress);
}

main().catch((err) => {
    console.error("Deployment failed:", err);
    process.exit(1);
});
