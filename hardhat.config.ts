import type { HardhatUserConfig } from "hardhat/config";
import hardhatToolboxViemPlugin from "@nomicfoundation/hardhat-toolbox-viem";
import * as dotenv from "dotenv";

dotenv.config();

const config: HardhatUserConfig = {
  // If the plugin pattern is correct per documentation:
  plugins: [hardhatToolboxViemPlugin],
  solidity: {
    profiles: {
      default: {
        version: "0.8.28",
        settings: {
          optimizer: { enabled: true, runs: 200 }
        }
      },
      production: {
        version: "0.8.28",
        settings: {
          optimizer: { enabled: true, runs: 200 }
        }
      }
    }
  },
  networks: {
    hardhatMainnet: { type: "edr-simulated", chainType: "l1" },
    hardhatOp: { type: "edr-simulated", chainType: "op" },
    bsctestnet: {
      type: "http", chainId: 97,
      url: process.env.BSCTESTNET_RPC_URL || "https://data-seed-prebsc-1-s1.binance.org:8545",
      accounts: process.env.BSCTESTNET_PRIVATE_KEY ? [process.env.BSCTESTNET_PRIVATE_KEY] : [],
      gasPrice: 20000000000,
      chainType: "l1"
    }
  },
  verify: {
    etherscan: {
      apiKey: process.env.BSCSCAN_API_KEY,
    },
  },
};

export default config;
