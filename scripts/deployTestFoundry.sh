#!/bin/bash
# Deploy escrow + test USDT to testnet
#
# Usage:
#   # Deploy both USDT + PalindromePay with verification (use bsc-testnet for bsc)
#   ./scripts/deployTestFoundry.sh base-test pk
#
#   # Deploy only PalindromePay (skip USDT)
#   ./scripts/deployTestFoundry.sh base-test pk --escrow-only
#
#   # Deploy without verification
#   ./scripts/deployTestFoundry.sh base-test pk --no-verify
#
#   # Combine both options
#   ./scripts/deployTestFoundry.sh base-test pk --escrow-only --no-verify


# Load environment variables
source .env

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fee receiver address
FEE_RECEIVER="${FREE_RECEIVER}"

if [ -z "$FEE_RECEIVER" ]; then
    echo -e "${RED}Error: FREE_RECEIVER not set in .env${NC}"
    exit 1
fi

export FEE_RECEIVER

# Deployer address (derived from OWNER_KEY)
if [ -n "$OWNER_KEY" ]; then
    DEPLOYER_ADDRESS=$(cast wallet address --private-key "$OWNER_KEY" 2>/dev/null)
fi

# Default options
ESCROW_ONLY=false
SKIP_VERIFY=false

# Parse optional flags
parse_flags() {
    for arg in "$@"; do
        case $arg in
            --escrow-only)
                ESCROW_ONLY=true
                ;;
            --no-verify)
                SKIP_VERIFY=true
                ;;
        esac
    done
}

print_usage() {
    echo ""
    echo "Usage: ./scripts/deployTestFoundry.sh <network> <method> [options]"
    echo ""
    echo "Networks (testnet only):"
    echo "  base-test   - Base Sepolia (testnet)"
    echo "  bsc-test    - BSC Testnet"
    echo ""
    echo "Methods:"
    echo "  trezor      - Deploy using Trezor hardware wallet"
    echo "  pk          - Deploy using private key from .env"
    echo ""
    echo "Options:"
    echo "  --escrow-only  - Deploy only PalindromePay (skip USDT)"
    echo "  --no-verify    - Skip contract verification"
    echo ""
    echo "Examples:"
    echo "  ./scripts/deployTestFoundry.sh base-test pk                    # Deploy USDT + Escrow"
    echo "  ./scripts/deployTestFoundry.sh base-test pk --escrow-only      # Deploy only Escrow"
    echo "  ./scripts/deployTestFoundry.sh bsc-test pk --no-verify         # Deploy without verification"
    echo "  ./scripts/deployTestFoundry.sh base-test pk --escrow-only --no-verify"
    echo ""
}

# Check arguments
if [ $# -lt 2 ]; then
    print_usage
    exit 1
fi

NETWORK=$1
METHOD=$2

# Parse optional flags
parse_flags "$@"

# Export flags for the Solidity script
export ESCROW_ONLY

# Set RPC URL and chain based on network (testnet only)
case $NETWORK in
    base-test)
        RPC_URL="${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}"
        CHAIN_ID=84532
        VERIFY_URL="https://api.etherscan.io/v2/api?chainid=84532"
        ETHERSCAN_KEY="${ETH_API_KEY}"
        NETWORK_NAME="Base Sepolia"
        ;;
    bsc-test)
        RPC_URL="${BSCTESTNET_RPC_URL:-https://data-seed-prebsc-1-s1.binance.org:8545}"
        CHAIN_ID=97
        VERIFY_URL="https://api.etherscan.io/v2/api?chainid=97"
        ETHERSCAN_KEY="${ETH_API_KEY}"
        NETWORK_NAME="BSC Testnet"
        GAS_PRICE="--with-gas-price 5000000000"
        ;;
    *)
        echo -e "${RED}Error: Unknown or unsupported network '$NETWORK'${NC}"
        echo -e "${YELLOW}This script only supports testnet deployments.${NC}"
        print_usage
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deploying to ${NETWORK_NAME} (TEST)${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Deployer: $DEPLOYER_ADDRESS"
echo "Fee Receiver: $FEE_RECEIVER"
echo "RPC URL: $RPC_URL"
echo "ETH API Key: $ETHERSCAN_KEY"
echo ""
echo -e "${YELLOW}This will deploy:${NC}"
if [ "$ESCROW_ONLY" = "true" ]; then
    echo "  - PalindromePay (escrow only)"
else
    echo "  - Test USDT (10,000,000 USDT, 6 decimals)"
    echo "  - PalindromePay"
fi
if [ "$SKIP_VERIFY" = "true" ]; then
    echo -e "${YELLOW}  (Verification: SKIPPED)${NC}"
fi
echo ""

# Build common forge command - select script based on escrow-only flag
if [ "$ESCROW_ONLY" = "true" ]; then
    FORGE_CMD="forge script scripts/Deploy.s.sol:DeployEscrow"
else
    FORGE_CMD="forge script scripts/DeployTest.s.sol:DeployTestEscrow"
fi
FORGE_CMD="$FORGE_CMD --rpc-url $RPC_URL"
FORGE_CMD="$FORGE_CMD --broadcast"
if [ "$SKIP_VERIFY" = "false" ]; then
    FORGE_CMD="$FORGE_CMD --verify"
    FORGE_CMD="$FORGE_CMD --verifier-url $VERIFY_URL"
    FORGE_CMD="$FORGE_CMD --etherscan-api-key $ETHERSCAN_KEY"
fi
FORGE_CMD="$FORGE_CMD -vvvv"
FORGE_CMD="$FORGE_CMD $GAS_PRICE"

# Add signing method
case $METHOD in
    trezor)
        echo -e "${YELLOW}Using Trezor - Please confirm on your device${NC}"
        FORGE_CMD="$FORGE_CMD --trezor"
        # Default derivation path for Ethereum
        FORGE_CMD="$FORGE_CMD --mnemonic-derivation-path \"m/44'/60'/0'/0/0\""
        ;;
    pk)
        if [ -z "$OWNER_KEY" ]; then
            echo -e "${RED}Error: OWNER_KEY not set in .env${NC}"
            exit 1
        fi
        echo "Using private key from .env"
        FORGE_CMD="$FORGE_CMD --private-key $OWNER_KEY"
        ;;
    *)
        echo -e "${RED}Error: Unknown method '$METHOD'. Use 'trezor' or 'pk'${NC}"
        print_usage
        exit 1
        ;;
esac

echo ""
echo -e "${YELLOW}Deploying and verifying automatically...${NC}"
echo ""

# Run the deployment with automatic verification
# Use tee to show output in real-time while capturing it
OUTPUT=$(eval $FORGE_CMD 2>&1 | tee /dev/tty)
DEPLOY_STATUS=${PIPESTATUS[0]}

# Check if deployment was successful (check for on-chain success even if verification fails)
if echo "$OUTPUT" | grep -q "ONCHAIN EXECUTION COMPLETE & SUCCESSFUL"; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Network: ${NETWORK_NAME}${NC}"
    echo -e "${GREEN}----------------------------------------${NC}"
    # Extract and display deployed contract addresses
    USDT_ADDR=$(echo "$OUTPUT" | grep "Test USDT:" | tail -1 | awk '{print $NF}')
    ESCROW_ADDR=$(echo "$OUTPUT" | grep "PalindromePay:" | tail -1 | awk '{print $NF}')
    START_BLOCK=$(echo "$OUTPUT" | grep "Start Block:" | tail -1 | awk '{print $NF}')
    if [ -n "$USDT_ADDR" ]; then
        echo -e "${GREEN}  Deployed Test USDT: $USDT_ADDR${NC}"
    fi
    if [ -n "$ESCROW_ADDR" ]; then
        echo -e "${GREEN}  Deployed PalindromePay: $ESCROW_ADDR${NC}"
    fi
    if [ -n "$START_BLOCK" ]; then
        echo -e "${GREEN}  Start Block: $START_BLOCK${NC}"
    fi
    echo -e "${GREEN}----------------------------------------${NC}"
    # Check if verification failed
    if echo "$OUTPUT" | grep -q "Not all.*contracts were verified"; then
        echo -e "${YELLOW}  Deployment Complete (Verification Failed)${NC}"
    else
        echo -e "${GREEN}  Test Deployment & Verification Complete!${NC}"
    fi
    echo -e "${GREEN}========================================${NC}"
elif [ $DEPLOY_STATUS -eq 0 ]; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Network: ${NETWORK_NAME}${NC}"
    echo -e "${GREEN}----------------------------------------${NC}"
    USDT_ADDR=$(echo "$OUTPUT" | grep "Test USDT:" | tail -1 | awk '{print $NF}')
    ESCROW_ADDR=$(echo "$OUTPUT" | grep "PalindromePay:" | tail -1 | awk '{print $NF}')
    START_BLOCK=$(echo "$OUTPUT" | grep "Start Block:" | tail -1 | awk '{print $NF}')
    if [ -n "$USDT_ADDR" ]; then
        echo -e "${GREEN}  Deployed Test USDT: $USDT_ADDR${NC}"
    fi
    if [ -n "$ESCROW_ADDR" ]; then
        echo -e "${GREEN}  Deployed PalindromePay: $ESCROW_ADDR${NC}"
    fi
    if [ -n "$START_BLOCK" ]; then
        echo -e "${GREEN}  Start Block: $START_BLOCK${NC}"
    fi
    echo -e "${GREEN}----------------------------------------${NC}"
    echo -e "${GREEN}  Test Deployment Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  Deployment Failed!${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi
