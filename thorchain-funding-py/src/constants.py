DEPOSIT_EVENT_ABI = '{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"asset\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"memo\",\"type\":\"string\"}],\"name\":\"Deposit\",\"type\":\"event\"}'
TRANSFER_OUT_EVENT_ABI = '{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"vault","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"address","name":"asset","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":false,"internalType":"string","name":"memo","type":"string"}],"name":"TransferOut","type":"event"}'

THORCHAIN_ROUTER_ADDRESS = {
    1: '0xd37bbe5744d730a1d98d8dc97c42f0ca46ad7146',
    56: '0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b',
    43114: '0x8f66c4ae756bebc49ec8b81966dd8bba9f127549'
}

# At the time of deployment thresholds are set to ~$150
THORCHAIN_THRESHOLDS = {
    1: 0.07,
    56: 0.5,
    43114: 4
}

PROTOCOLS = {
    1: 'ethereum',
    56: 'binance smart chain',
    43114: 'avalanche'
}

CURRENCIES = {
    1: "ETH",
    56: "BSC",
    43114: "AVAX"
}
