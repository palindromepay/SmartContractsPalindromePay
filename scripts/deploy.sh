#!/bin/bash
#./scripts/deploy.sh bsc-test pk
#./scripts/deploy.sh base-test pk
#./scripts/deploy.sh base-test trezor
#./scripts/deploy.sh bsc-test trezor

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

print_usage() {
    echo ""
    echo "Usage: ./scripts/deploy.sh <network> <method>"
    echo ""
    echo "Networks:"
    echo "  base        - Base Mainnet"
    echo "  bsc         - BSC Mainnet"
    echo "  base-test   - Base Sepolia (testnet)"
    echo "  bsc-test    - BSC Testnet"
    echo ""
    echo "Methods:"
    echo "  trezor      - Deploy using Trezor hardware wallet"
    echo "  pk          - Deploy using private key from .env"
    echo ""
    echo "Examples:"
    echo "  ./scripts/deploy.sh base trezor      # Deploy to Base with Trezor"
    echo "  ./scripts/deploy.sh bsc pk           # Deploy to BSC with private key"
    echo "  ./scripts/deploy.sh base-test pk     # Deploy to Base Sepolia testnet"
    echo ""
}

# Check arguments
if [ $# -lt 2 ]; then
    print_usage
    exit 1
fi

NETWORK=$1
METHOD=$2

# Set RPC URL and chain based on network
case $NETWORK in
    base)
        RPC_URL="https://mainnet.base.org"
        CHAIN_ID=8453
        VERIFY_URL="https://api.etherscan.io/v2/api?chainid=8453"
        ETHERSCAN_KEY="${ETH_API_KEY}"
        NETWORK_NAME="Base Mainnet"
        ;;
    bsc)
        RPC_URL="https://bsc-dataseed.binance.org"
        CHAIN_ID=56
        VERIFY_URL="https://api.etherscan.io/v2/api?chainid=56"
        ETHERSCAN_KEY="${ETH_API_KEY}"
        NETWORK_NAME="BSC Mainnet"
        ;;
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
        ;;
    *)
        echo -e "${RED}Error: Unknown network '$NETWORK'${NC}"
        print_usage
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deploying to ${NETWORK_NAME}${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Fee Receiver: $FEE_RECEIVER"
echo "RPC URL: $RPC_URL"
echo ""

# Build common forge command
FORGE_CMD="forge script scripts/Deploy.s.sol:DeployEscrow"
FORGE_CMD="$FORGE_CMD --rpc-url $RPC_URL"
FORGE_CMD="$FORGE_CMD --broadcast"
FORGE_CMD="$FORGE_CMD --verify"
FORGE_CMD="$FORGE_CMD --verifier-url $VERIFY_URL"
FORGE_CMD="$FORGE_CMD --etherscan-api-key $ETHERSCAN_KEY"
FORGE_CMD="$FORGE_CMD -vvvv"

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
eval $FORGE_CMD

# Check if deployment was successful
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Deployment & Verification Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  Deployment Failed!${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi
