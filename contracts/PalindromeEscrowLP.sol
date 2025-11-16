// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @notice LP token representing protocol fee share.
 * @dev Only the designated minter (escrow contract) can mint and burn.
 */
contract PalindromeEscrowLP is ERC20, Ownable {
    address public minter;

    constructor() ERC20("Palindrome LP Token", "PLP") {}

    /// @notice Sets the authorized minter (escrow contract)
    function setMinter(address _minter) external onlyOwner {
        minter = _minter;
    }

    /// @notice Mint LP tokens; only callable by the current minter.
    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "Only minter");
        _mint(to, amount);
    }

    /// @notice Burn LP tokens; only callable by the current minter.
    function burn(address from, uint256 amount) external {
        require(msg.sender == minter, "Only minter");
        _burn(from, amount);
    }
}
