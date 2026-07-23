// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice ERC20 that skims a fee (in bps) from every transfer amount and
///         credits it to a sink address. Recipients receive amount - fee, so
///         the escrow's balance-delta measurement ("received") is exercised.
contract FeeOnTransferToken is ERC20 {
    uint256 public immutable FEE_BPS;
    address public immutable FEE_SINK;
    uint8 private immutable _DECIMALS;

    constructor(uint256 feeBps, address feeSink, uint8 decimals_) ERC20("FeeToken", "FEE") {
        require(feeBps < 10_000, "fee too high");
        FEE_BPS = feeBps;
        FEE_SINK = feeSink;
        _DECIMALS = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _DECIMALS;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 fee = (amount * FEE_BPS) / 10_000;
        if (fee > 0) {
            super._transfer(from, FEE_SINK, fee);
        }
        super._transfer(from, to, amount - fee);
    }
}
