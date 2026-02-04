// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract USDT is ERC20 {
    uint8 private _decimals;

    uint256 public constant FAUCET_AMOUNT = 10000; // 10000 tokens (before decimals)
    uint256 public constant FAUCET_COOLDOWN = 1 hours;

    mapping(address => uint256) public lastFaucetTime;

    constructor(
        string memory name,
        string memory symbol,
        uint256 initialSupply,
        uint8 decimals_
    ) ERC20(name, symbol) {
        _decimals = decimals_;
        _mint(msg.sender, initialSupply);
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    /// @notice Mint test tokens (faucet for testing)
    /// @dev Anyone can call once per hour
    function faucet() external {
        require(
            block.timestamp >= lastFaucetTime[msg.sender] + FAUCET_COOLDOWN,
            "Faucet: cooldown active"
        );

        lastFaucetTime[msg.sender] = block.timestamp;
        _mint(msg.sender, FAUCET_AMOUNT * (10 ** _decimals));
    }

    /// @notice Mint tokens to a specific address (for testing)
    /// @param to Recipient address
    /// @param amount Amount to mint (in smallest units)
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
