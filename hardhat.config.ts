import type { HardhatUserConfig } from "hardhat/config";
import hardhatToolboxViemPlugin from "@nomicfoundation/hardhat-toolbox-viem";
import * as dotenv from "dotenv";

dotenv.config();

const config: HardhatUserConfig = {
  plugins: [hardhatToolboxViemPlugin],
  solidity: {
    compilers: [
      {
        version: "0.8.29",
        settings: {
          optimizer: { enabled: true, runs: 200 },
          viaIR: true,
          evmVersion: "cancun"
        },
      },
    ],
  },
  networks: {
    hardhatMainnet: { type: "edr-simulated", chainType: "l1" },
    hardhatOp: { type: "edr-simulated", chainType: "op" },
    // BSC Testnet
    bscTestnet: {
      type: "http",
      chainId: 97,
      url: process.env.BSCTESTNET_RPC_URL || "https://data-seed-prebsc-1-s1.binance.org:8545",
      accounts: process.env.OWNER_KEY ? [process.env.OWNER_KEY] : [],
      gasPrice: 20000000000,
      chainType: "l1",
    },
    // Base Sepolia (testnet)
    baseSepolia: {
      type: "http",
      chainId: 84532,
      url: process.env.BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org",
      accounts: process.env.OWNER_KEY ? [process.env.OWNER_KEY] : [],
      chainType: "op",
    },
    // Ethereum Sepolia (testnet)
    sepolia: {
      type: "http",
      chainId: 11155111,
      url: process.env.ETH_SEPOLIA_RPC_URL || "https://rpc.sepolia.org",
      accounts: process.env.OWNER_KEY ? [process.env.OWNER_KEY] : [],
      chainType: "l1",
    },
    // BSC Mainnet
    bsc: {
      type: "http",
      chainId: 56,
      url: process.env.BSC_RPC_URL || "https://bsc-dataseed.binance.org",
      accounts: process.env.OWNER_KEY ? [process.env.OWNER_KEY] : [],
      chainType: "l1",
    },
    // Base Mainnet
    base: {
      type: "http",
      chainId: 8453,
      url: process.env.BASE_RPC_URL || "https://mainnet.base.org",
      accounts: process.env.OWNER_KEY ? [process.env.OWNER_KEY] : [],
      chainType: "op",
    },
    // Ethereum Mainnet
    mainnet: {
      type: "http",
      chainId: 1,
      url: process.env.ETH_RPC_URL || "https://eth.llamarpc.com",
      accounts: process.env.OWNER_KEY ? [process.env.OWNER_KEY] : [],
      chainType: "l1",
    },
  },
};

export default config;