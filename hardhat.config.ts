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
        },
      },
    ],
  },
  networks: {
    hardhatMainnet: { type: "edr-simulated", chainType: "l1" },
    hardhatOp: { type: "edr-simulated", chainType: "op" },
    bsctestnet: {
      type: "http",
      chainId: 97,
      url: process.env.BSCTESTNET_RPC_URL || "https://data-seed-prebsc-1-s1.binance.org:8545",
      accounts: process.env.BSCTESTNET_PRIVATE_KEY ? [process.env.BSCTESTNET_PRIVATE_KEY] : [],
      gasPrice: 20000000000,
      chainType: "l1",
    },
    baseSepolia: {
      type: "http",
      chainId: 84532,
      url: process.env.BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org",
      accounts: process.env.OWNER_KEY ? [process.env.OWNER_KEY] : [],
      chainType: "op",
    },
  },
  verify: {
    etherscan: {
      apiKey: process.env.ETHERSCAN_API_KEY || process.env.BSCSCAN_API_KEY,
    },
  },
};

export default config;