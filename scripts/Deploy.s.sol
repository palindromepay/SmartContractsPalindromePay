// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/**
source .env && forge verify-contract 0x32C34C69F9e7906fc33E09719882d581922EaF03 contracts/PalindromeCryptoEscrow.sol:PalindromeCryptoEscrow \
  --verifier-url "https://api.etherscan.io/v2/api?chainid=97" \
  --etherscan-api-key "$ETH_API_KEY" \
  --constructor-args 0x0000000000000000000000003ec903a8beb19d7f30033e1f882cd1b0c61cebe4
 */

import "forge-std/Script.sol";
import "../contracts/PalindromeCryptoEscrow.sol";

contract DeployEscrow is Script {
    function run() external {
        // Load fee receiver from environment
        address feeReceiver = vm.envAddress("FEE_RECEIVER");
        require(feeReceiver != address(0), "FEE_RECEIVER not set");

        console.log("Deploying PalindromeCryptoEscrow...");
        console.log("Fee Receiver:", feeReceiver);

        vm.startBroadcast();

        PalindromeCryptoEscrow escrow = new PalindromeCryptoEscrow(feeReceiver);

        vm.stopBroadcast();

        console.log("========== Deployment Complete ==========");
        console.log("PalindromeCryptoEscrow:", address(escrow));
        console.log("Fee Receiver:", feeReceiver);
        console.log("=========================================");
    }
}
