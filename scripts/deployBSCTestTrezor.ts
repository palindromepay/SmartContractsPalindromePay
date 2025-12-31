import * as dotenv from "dotenv";
dotenv.config();

import "@nomicfoundation/hardhat-toolbox-viem";
import hre from "hardhat";

const feeReceiver = process.env.FREE_RECEIVER?.trim();

if (!feeReceiver) {
    throw new Error("Set FREE_RECEIVER in environment");
}

async function main() {
    console.log("Deploying contracts using Trezor...");
    console.log("Please confirm transactions on your Trezor device.\n");

    const USDT_INITIAL_SUPPLY = 10_000_000n * 10n ** 6n; // 10 million tokens with 6 decimals

    // 1. Deploy USDT
    console.log("Deploying USDT...");
    const usdt = await (hre as any).viem.deployContract("USDT", [
        "Tether USD",
        "USDT",
        USDT_INITIAL_SUPPLY,
        6,
    ]);
    console.log("USDT deployed at:", usdt.address);

    // 2. Deploy PalindromeCryptoEscrow
    console.log("\nDeploying PalindromeCryptoEscrow...");
    const escrow = await (hre as any).viem.deployContract("PalindromeCryptoEscrow", [
        feeReceiver,
    ]);
    console.log("PalindromeCryptoEscrow deployed at:", escrow.address);

    // 3. Wait for block explorer to index the contracts
    console.log("\nWaiting 30 seconds for block explorer to index...");
    await new Promise((resolve) => setTimeout(resolve, 30000));

    // 4. Verify USDT
    console.log("\nVerifying USDT...");
    try {
        await (hre as any).run("verify:verify", {
            address: usdt.address,
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

    // 5. Verify PalindromeCryptoEscrow
    console.log("\nVerifying PalindromeCryptoEscrow...");
    try {
        await (hre as any).run("verify:verify", {
            address: escrow.address,
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
    console.log("\n========== Deployment Summary ==========");
    console.log("USDT:", usdt.address);
    console.log("PalindromeCryptoEscrow:", escrow.address);
    console.log("Fee Receiver:", feeReceiver);
    console.log("=========================================");
}

main().catch((err) => {
    console.error("Deployment failed:", err);
    process.exit(1);
});
