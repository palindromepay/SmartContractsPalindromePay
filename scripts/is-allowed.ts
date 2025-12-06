import * as dotenv from "dotenv";
dotenv.config();

import { createPublicClient, createWalletClient, http, encodeFunctionData } from "viem";
import { bscTestnet } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";

function loadArtifact(path: string) {
    return JSON.parse(readFileSync(path, "utf8"));
}
const EscrowArtifact = loadArtifact("./artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json");

const BSCTESTNET_RPC_URL = process.env.BSCTESTNET_RPC_URL?.trim();
const BSCTESTNET_PRIVATE_KEY = process.env.OWNER_KEY?.trim();

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
const publicClient = createPublicClient({ chain: bscTestnet, transport: http(BSCTESTNET_RPC_URL) });
const deployerAccount = privateKeyToAccount(privateKey);
const deployerClient = createWalletClient({ chain: bscTestnet, transport: http(BSCTESTNET_RPC_URL), account: deployerAccount });

async function checkTokenAllowed(escrowAddress: `0x${string}`, tokenAddress: `0x${string}`) {
    const isAllowed = await publicClient.readContract({
        address: escrowAddress,
        abi: EscrowArtifact.abi,
        functionName: "allowedTokens",
        args: [tokenAddress],
    });
    console.log(`Token ${tokenAddress} allowed:`, isAllowed);
    return isAllowed;
}

async function main() {
    const ESCROW_ADDRESS = "0xc3436fa373dbf363922d4095c75f6339b3d97055" as `0x${string}`; // Update with your deployed escrow address
    const TOKEN_TO_CHECK = "0x0b2d5f8c70a5cb55de506527b0474c811c3272da" as `0x${string}`; // Token address to check

    await checkTokenAllowed(ESCROW_ADDRESS, TOKEN_TO_CHECK);
}

main().catch(console.error);
