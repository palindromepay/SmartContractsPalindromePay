/**
 * PalindromePay Deployment Script (Hardhat + viem)
 *
 * Usage:
 *   # Local Hardhat node (start with: npx hardhat node)
 *   npx ts-node scripts/deploy.ts local
 *   npx ts-node scripts/deploy.ts local --escrow-only
 *
 *   # Deploy both USDT + PalindromePay with verification
 *   npx ts-node scripts/deploy.ts base-test
 *   npx ts-node scripts/deploy.ts bsc-test
 *   npx ts-node scripts/deploy.ts eth-test
 *
 *   # Deploy only PalindromePay (skip USDT)
 *   npx ts-node scripts/deploy.ts base-test --escrow-only
 *
 *   # Deploy only USDT (skip PalindromePay)
 *   npx ts-node scripts/deploy.ts base-test --usdt-only
 *
 *   # Deploy without verification
 *   npx ts-node scripts/deploy.ts base-test --no-verify
 *
 *   # Combine options
 *   npx ts-node scripts/deploy.ts bsc-test --escrow-only --no-verify
 *
 * Networks:
 *   local       - Local Hardhat node (http://127.0.0.1:8545)
 *   eth-test    - Ethereum Sepolia (testnet)
 *   base-test   - Base Sepolia (testnet)
 *   bsc-test    - BSC Testnet
 *   eth         - Ethereum Mainnet
 *   base        - Base Mainnet
 *   bsc         - BSC Mainnet
 *
 * Required Environment Variables:
 *   OWNER_KEY            - Deployer private key (not needed for local)
 *   FREE_RECEIVER        - Fee receiver address (not needed for local)
 *   ETH_SEPOLIA_RPC_URL  - Ethereum Sepolia RPC URL
 *   ETH_RPC_URL          - Ethereum Mainnet RPC URL
 *   BSCTESTNET_RPC_URL   - BSC Testnet RPC URL
 *   BASE_SEPOLIA_RPC_URL - Base Sepolia RPC URL
 *   BSC_RPC_URL          - BSC Mainnet RPC URL
 *   BASE_RPC_URL         - Base Mainnet RPC URL
 *   ETHERSCAN_API_KEY    - Etherscan V2 API key (works for all chains)
 */

import * as dotenv from "dotenv";
dotenv.config();

import {
    createPublicClient,
    createWalletClient,
    http,
    type PublicClient,
    type WalletClient,
    type Chain,
    type Account,
    type Hex,
} from "viem";
import { bscTestnet, baseSepolia, bsc, base, hardhat, sepolia, mainnet } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "fs";
import { execSync } from "child_process";

// =============================================================================
// Configuration
// =============================================================================

// Local hardhat default private key (account #2)
const LOCAL_DEPLOYER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

interface NetworkConfig {
    chain: Chain;
    rpcUrl: string;
    explorerApiUrl: string;
    explorerApiKey: string;
    explorerUrl: string;
    isLocal?: boolean;
    localPrivateKey?: string;
}

const NETWORKS: Record<string, NetworkConfig> = {
    "local": {
        chain: hardhat,
        rpcUrl: "http://127.0.0.1:8545",
        explorerApiUrl: "",
        explorerApiKey: "",
        explorerUrl: "",
        isLocal: true,
        localPrivateKey: LOCAL_DEPLOYER_KEY,
    },
    "bsc-test": {
        chain: bscTestnet,
        rpcUrl: process.env.BSCTESTNET_RPC_URL || "",
        explorerApiUrl: "https://api-testnet.bscscan.com/api",
        explorerApiKey: process.env.ETHERSCAN_API_KEY || "",
        explorerUrl: "https://testnet.bscscan.com",
    },
    "base-test": {
        chain: baseSepolia,
        rpcUrl: process.env.BASE_SEPOLIA_RPC_URL || "",
        explorerApiUrl: "https://api-sepolia.basescan.org/api",
        explorerApiKey: process.env.ETHERSCAN_API_KEY || "",
        explorerUrl: "https://sepolia.basescan.org",
    },
    "eth-test": {
        chain: sepolia,
        rpcUrl: process.env.ETH_SEPOLIA_RPC_URL || "",
        explorerApiUrl: "https://api-sepolia.etherscan.io/api",
        explorerApiKey: process.env.ETHERSCAN_API_KEY || "",
        explorerUrl: "https://sepolia.etherscan.io",
    },
    "bsc": {
        chain: bsc,
        rpcUrl: process.env.BSC_RPC_URL || "",
        explorerApiUrl: "https://api.bscscan.com/api",
        explorerApiKey: process.env.ETHERSCAN_API_KEY || "",
        explorerUrl: "https://bscscan.com",
    },
    "base": {
        chain: base,
        rpcUrl: process.env.BASE_RPC_URL || "",
        explorerApiUrl: "https://api.basescan.org/api",
        explorerApiKey: process.env.ETHERSCAN_API_KEY || "",
        explorerUrl: "https://basescan.org",
    },
    "eth": {
        chain: mainnet,
        rpcUrl: process.env.ETH_RPC_URL || "",
        explorerApiUrl: "https://api.etherscan.io/api",
        explorerApiKey: process.env.ETHERSCAN_API_KEY || "",
        explorerUrl: "https://etherscan.io",
    },
};

// Colors for terminal output
const colors = {
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    reset: "\x1b[0m",
};

// =============================================================================
// Helpers
// =============================================================================

function loadArtifact(path: string) {
    return JSON.parse(readFileSync(path, "utf8"));
}

function validateHexKey(key: string | undefined, label: string): Hex {
    if (!key) throw new Error(`Missing ${label}`);
    const stripped = key.replace(/^['"]|['"]$/g, "").trim();
    if (!/^0x[0-9a-fA-F]{64}$/.test(stripped)) {
        throw new Error(`Invalid format for ${label}: must be 0x + 64 hex chars`);
    }
    return stripped as Hex;
}

function validateAddress(addr: string | undefined, label: string): Hex {
    if (!addr) throw new Error(`Missing ${label}`);
    const stripped = addr.replace(/^['"]|['"]$/g, "").trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(stripped)) {
        throw new Error(`Invalid format for ${label}: must be 0x + 40 hex chars`);
    }
    return stripped as Hex;
}

function printUsage() {
    console.log(`
Usage: npx ts-node scripts/deploy.ts <network> [options]

Networks:
  local       - Local Hardhat node (http://127.0.0.1:8545)
  eth-test    - Ethereum Sepolia (testnet)
  base-test   - Base Sepolia (testnet)
  bsc-test    - BSC Testnet
  eth         - Ethereum Mainnet
  base        - Base Mainnet
  bsc         - BSC Mainnet

Options:
  --escrow-only  - Deploy only PalindromePay (skip USDT)
  --usdt-only    - Deploy only USDT (skip PalindromePay)
  --no-verify    - Skip contract verification
  --with-usdt    - Deploy test USDT token (default for testnets/local)

Examples:
  npx ts-node scripts/deploy.ts local                             # Local: USDT + Escrow
  npx ts-node scripts/deploy.ts local --escrow-only               # Local: only Escrow
  npx ts-node scripts/deploy.ts base-test --usdt-only             # Deploy only USDT
  npx ts-node scripts/deploy.ts eth-test                          # Deploy USDT + Escrow with verify
  npx ts-node scripts/deploy.ts base-test                         # Deploy USDT + Escrow with verify
  npx ts-node scripts/deploy.ts base-test --escrow-only           # Deploy only Escrow
  npx ts-node scripts/deploy.ts bsc-test --no-verify              # Deploy without verification
  npx ts-node scripts/deploy.ts base-test --escrow-only --no-verify
`);
}

// =============================================================================
// Deploy Functions
// =============================================================================

async function deployContract(
    publicClient: PublicClient,
    walletClient: WalletClient,
    account: Account,
    chain: Chain,
    { abi, bytecode, args = [] }: { abi: any; bytecode: Hex; args?: any[] }
): Promise<{ address: Hex; blockNumber: bigint; txHash: Hex }> {
    console.log("  Deploying contract...");

    const hash = await walletClient.deployContract({
        abi,
        bytecode,
        args,
        account,
        chain,
    });

    console.log(`  Transaction hash: ${hash}`);
    console.log("  Waiting for confirmation...");

    const receipt = await publicClient.waitForTransactionReceipt({ hash });

    if (!receipt.contractAddress) {
        throw new Error("Deployment failed: No contract address in receipt");
    }

    return {
        address: receipt.contractAddress as Hex,
        blockNumber: receipt.blockNumber,
        txHash: hash,
    };
}

// =============================================================================
// Verification
// =============================================================================

async function verifyContract(
    network: NetworkConfig,
    contractAddress: Hex,
    contractName: string,
    constructorArgs: any[],
    contractPath: string
): Promise<boolean> {
    if (!network.explorerApiKey) {
        console.log(`  ${colors.yellow}Warning: No API key for verification${colors.reset}`);
        return false;
    }

    console.log(`  Verifying ${contractName}...`);

    try {
        // Use hardhat verify command
        const argsStr = constructorArgs.map(arg => `"${arg}"`).join(" ");
        const cmd = `npx hardhat verify --network ${getHardhatNetwork(network.chain.id)} ${contractAddress} ${argsStr}`;

        console.log(`  Running: ${cmd}`);
        execSync(cmd, { stdio: "inherit" });

        console.log(`  ${colors.green}✓ Verified ${contractName}${colors.reset}`);
        return true;
    } catch (error: any) {
        // Check if already verified
        if (error.message?.includes("Already Verified") || error.stdout?.includes("Already Verified")) {
            console.log(`  ${colors.green}✓ Already verified${colors.reset}`);
            return true;
        }
        console.log(`  ${colors.yellow}Verification failed: ${error.message || error}${colors.reset}`);
        return false;
    }
}

function getHardhatNetwork(chainId: number): string {
    const mapping: Record<number, string> = {
        1: "mainnet",
        97: "bscTestnet",
        84532: "baseSepolia",
        11155111: "sepolia",
        56: "bsc",
        8453: "base",
    };
    return mapping[chainId] || "unknown";
}

// =============================================================================
// Main
// =============================================================================

async function main() {
    // Parse CLI args
    const args = process.argv.slice(2);

    if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
        printUsage();
        process.exit(0);
    }

    const networkName = args[0];
    const escrowOnly = args.includes("--escrow-only");
    const usdtOnly = args.includes("--usdt-only");
    const skipVerify = args.includes("--no-verify");
    const withUsdt = args.includes("--with-usdt");

    // Validate network
    const network = NETWORKS[networkName];
    if (!network) {
        console.error(`${colors.red}Error: Unknown network: ${networkName}${colors.reset}`);
        console.error(`Available networks: ${Object.keys(NETWORKS).join(", ")}`);
        process.exit(1);
    }

    // Validate mutually exclusive options
    if (escrowOnly && usdtOnly) {
        console.error(`${colors.red}Error: Cannot use --escrow-only and --usdt-only together${colors.reset}`);
        process.exit(1);
    }

    // Determine what to deploy
    const isTestnet = networkName.includes("test") || networkName === "local";
    const deployUsdt = usdtOnly || (!escrowOnly && (withUsdt || isTestnet));
    const deployEscrow = !usdtOnly;

    // Local network automatically skips verification
    const shouldSkipVerify = skipVerify || network.isLocal;

    if (!network.rpcUrl) {
        throw new Error(`Missing RPC URL for network ${networkName}. Check your .env file.`);
    }

    console.log("========================================");
    console.log("  PalindromePay Deployment");
    console.log("========================================");
    console.log(`  Network:      ${networkName}`);
    console.log(`  Chain ID:     ${network.chain.id}`);
    console.log(`  Deploy USDT:  ${deployUsdt ? "Yes" : "No"}`);
    console.log(`  Deploy Escrow: ${deployEscrow ? "Yes" : "No"}`);
    console.log(`  Verify:       ${shouldSkipVerify ? "No" : "Yes"}`);
    console.log("========================================\n");

    // Load artifacts
    const PalindromePayArtifact = loadArtifact(
        "./artifacts/contracts/PalindromePay.sol/PalindromePay.json"
    );
    const USDTArtifact = loadArtifact(
        "./artifacts/contracts/USDT.sol/USDT.json"
    );

    // Setup accounts - use local key for local network
    const privateKey = network.isLocal
        ? (network.localPrivateKey as Hex)
        : validateHexKey(process.env.OWNER_KEY, "OWNER_KEY");

    // For local network, use deployer as fee receiver if not set
    const feeReceiver = network.isLocal && !process.env.FREE_RECEIVER
        ? privateKeyToAccount(privateKey).address
        : validateAddress(process.env.FREE_RECEIVER, "FREE_RECEIVER");

    const deployerAccount = privateKeyToAccount(privateKey);
    console.log(`Deployer:     ${deployerAccount.address}`);
    console.log(`Fee Receiver: ${feeReceiver}\n`);

    // Setup clients
    const publicClient = createPublicClient({
        chain: network.chain,
        transport: http(network.rpcUrl),
    });

    const walletClient = createWalletClient({
        chain: network.chain,
        transport: http(network.rpcUrl),
        account: deployerAccount,
    });

    // Check deployer balance
    const balance = await publicClient.getBalance({ address: deployerAccount.address });
    const balanceFormatted = (Number(balance) / 1e18).toFixed(4);
    console.log(`Balance:      ${balanceFormatted} ${network.chain.nativeCurrency.symbol}\n`);

    if (balance === 0n) {
        throw new Error("Deployer has no balance for gas fees");
    }

    let usdtAddress: Hex | undefined;
    let escrowAddress: Hex | undefined;
    let startBlock: bigint | undefined;

    // Deploy USDT if requested
    if (deployUsdt) {
        console.log("--- Deploying Test USDT ---");
        const USDT_INITIAL_SUPPLY = 10_000_000n * 10n ** 6n; // 10M with 6 decimals
        const usdtArgs = ["Test USDT", "USDT", USDT_INITIAL_SUPPLY, 6];

        const usdt = await deployContract(
            publicClient,
            walletClient,
            deployerAccount,
            network.chain,
            {
                abi: USDTArtifact.abi,
                bytecode: USDTArtifact.bytecode as Hex,
                args: usdtArgs,
            }
        );
        usdtAddress = usdt.address;
        console.log(`  ${colors.green}✓ Test USDT: ${usdtAddress}${colors.reset}\n`);

        // Verify USDT
        if (!shouldSkipVerify) {
            await verifyContract(
                network,
                usdtAddress,
                "USDT",
                usdtArgs,
                "contracts/USDT.sol:USDT"
            );
            console.log();
        }
    }

    // Deploy PalindromePay if requested
    if (deployEscrow) {
        console.log("--- Deploying PalindromePay ---");
        const escrowArgs = [feeReceiver];

        const escrow = await deployContract(
            publicClient,
            walletClient,
            deployerAccount,
            network.chain,
            {
                abi: PalindromePayArtifact.abi,
                bytecode: PalindromePayArtifact.bytecode as Hex,
                args: escrowArgs,
            }
        );
        escrowAddress = escrow.address;
        startBlock = escrow.blockNumber;
        console.log(`  ${colors.green}✓ PalindromePay: ${escrowAddress}${colors.reset}\n`);

        // Verify PalindromePay
        if (!shouldSkipVerify) {
            await verifyContract(
                network,
                escrowAddress,
                "PalindromePay",
                escrowArgs,
                "contracts/PalindromePay.sol:PalindromePay"
            );
            console.log();
        }
    }

    // Summary
    console.log("========================================");
    console.log(`  ${colors.green}Deployment Complete!${colors.reset}`);
    console.log("========================================");
    if (usdtAddress) {
        console.log(`  Test USDT:      ${usdtAddress}`);
    }
    if (escrowAddress) {
        console.log(`  PalindromePay:  ${escrowAddress}`);
        console.log(`  Start Block:    ${startBlock}`);
    }
    console.log(`  Network:        ${networkName}`);
    console.log(`  Chain ID:       ${network.chain.id}`);
    if (network.explorerUrl && (escrowAddress || usdtAddress)) {
        console.log("----------------------------------------");
        const displayAddress = escrowAddress || usdtAddress;
        console.log(`  Explorer: ${network.explorerUrl}/address/${displayAddress}`);
    }
    console.log("========================================\n");

    // Output for easy copy-paste
    console.log("Environment variables for SDK:");
    console.log("----------------------------------------");
    if (escrowAddress) {
        console.log(`CONTRACT_ADDRESS=${escrowAddress}`);
        console.log(`START_BLOCK=${startBlock}`);
    }
    if (usdtAddress) {
        console.log(`USDT_ADDRESS=${usdtAddress}`);
    }
    console.log(`CHAIN_ID=${network.chain.id}`);
}

main().catch((err) => {
    console.error(`\n${colors.red}Deployment failed:${colors.reset}`, err.message || err);
    process.exit(1);
});
