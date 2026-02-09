// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {PalindromePayWallet} from "./PalindromePayWallet.sol";

/**
 * @title PalindromePayWalletFactory
 * @notice Factory for deploying PalindromePayWallet instances via CREATE2.
 * @dev Extracted from PalindromePay to keep the main contract under the
 *      24 KB EIP-170 bytecode limit. The wallet's ESCROW_CONTRACT immutable
 *      is set to msg.sender (the escrow contract calling deploy).
 */
contract PalindromePayWalletFactory {

    /// @notice Deploys a new wallet for the given escrow ID
    /// @dev The caller (msg.sender) becomes the wallet's ESCROW_CONTRACT
    /// @param escrowId The escrow ID used as CREATE2 salt
    /// @return walletAddr The deployed wallet address
    function deploy(uint256 escrowId) external returns (address walletAddr) {
        bytes32 salt = keccak256(abi.encodePacked(escrowId));

        bytes memory bytecode = abi.encodePacked(
            type(PalindromePayWallet).creationCode,
            abi.encode(msg.sender, escrowId)
        );

        assembly ("memory-safe") {
            let codePtr := add(bytecode, 0x20)
            let codeSize := mload(bytecode)
            walletAddr := create2(0, codePtr, codeSize, salt)
            if iszero(walletAddr) { revert(0, 0) }
        }
    }

    /// @notice Predicts the wallet address before deployment
    /// @param escrowContract The escrow contract that will call deploy()
    /// @param escrowId The escrow ID
    /// @return predicted The deterministic wallet address
    function predictWalletAddress(
        address escrowContract,
        uint256 escrowId
    ) external view returns (address predicted) {
        bytes32 salt = keccak256(abi.encodePacked(escrowId));
        bytes32 bytecodeHash = keccak256(
            abi.encodePacked(
                type(PalindromePayWallet).creationCode,
                abi.encode(escrowContract, escrowId)
            )
        );
        predicted = address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, bytecodeHash)
        ))));
    }
}
