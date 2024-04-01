
WITHDRAW_ETH_FUNCTION_ABI = '{\"inputs\":[{\"internalType\":\"address\",\"name\":\"destination\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"withdrawETH\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}'

ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

SWFT_SWAP_ADDRESS = {
    1: '0x92e929d8b2c8430bcaf4cd87654789578bb2b786',
    10: '0x8f957ed3f969d7b6e5d6df81e61a5ff45f594dd1',
    56: '0x1ed5685f345b2fa564ea4a670de1fde39e484751',
    137: '0x242ea2a8c4a3377a738ed8a0d8cc0fe8b4d6c36e',
    250: '0x8f957ed3f969d7b6e5d6df81e61a5ff45f594dd1',
    42161: '0x8f957ed3f969d7b6e5d6df81e61a5ff45f594dd1',
    43114: '0x8f957ed3f969d7b6e5d6df81e61a5ff45f594dd1'
}

# At the time of deployment thresholds are set to ~$150
SWFT_SWAP_THRESHOLDS = {
    1: 0.07,
    10: 0.07,
    56: 0.5,
    137: 190,
    250: 400,
    42161: 0.07,
    43114: 4,
}

PROTOCOLS = {
    1: 'ethereum',
    10: 'optimism',
    56: 'binance smart chain',
    137: 'polygon',
    250: 'fantom',
    42161: 'arbitrum',
    43114: 'avalanche'
}

CURRENCIES = {
    1: "ETH",
    10: "ETH",
    56: "BNB",
    137: "MATIC",
    250: "FTM",
    42161: "ETH",
    43114: "AVAX"
}
