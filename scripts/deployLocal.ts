import {
    createPublicClient,
    createWalletClient,
    http,
} from "viem";
import { hardhat } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";
import type { Address } from "viem";

// --- Load contract artifacts ---
function loadArtifact(path: string) {
    return JSON.parse(readFileSync(path, "utf8"));
}
const EscrowArtifact = loadArtifact("./artifacts/contracts/PalindromeCryptoEscrow.sol/PalindromeCryptoEscrow.json");
const USDTArtifact = loadArtifact("./artifacts/contracts/USDT.sol/USDT.json");

const publicClient = createPublicClient({
    chain: hardhat,
    transport: http("http://127.0.0.1:8545"),
});

// --- Simple deploy helper ---
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
    return { address: receipt.contractAddress as `0x${string}` };
}

async function main() {
    const DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const deployerAccount = privateKeyToAccount(DEPLOYER_KEY);

    const deployerClient = createWalletClient({
        chain: hardhat,
        transport: http(),
        account: deployerAccount,
    });

    // --- Deploy USDT (name, symbol, initialSupply) ---
    const USDT_INITIAL_SUPPLY = 10_000_000 * 1_000_000; // 10M USDT * 10^6 (6 decimals)
    const usdt = await deployContract(deployerClient, {
        abi: USDTArtifact.abi,
        bytecode: USDTArtifact.bytecode,
        args: ["Tether USD", "USDT", USDT_INITIAL_SUPPLY],
    });
    const usdtAddress = usdt.address;

    // --- Deploy Escrow contract (no constructor args) ---
    const escrow = await deployContract(deployerClient, {
        abi: EscrowArtifact.abi,
        bytecode: EscrowArtifact.bytecode,
    });
    const escrowAddress = escrow.address;

    // --- Print addresses for frontend/verification ---
    console.log(`USDT deployed to:         ${usdtAddress}`);
    console.log(`PalindromeCryptoEscrow deployed to: ${escrowAddress}`);

    // --- Optionally, mint or transfer tokens here if needed, using deployerClient.writeContract ---
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
