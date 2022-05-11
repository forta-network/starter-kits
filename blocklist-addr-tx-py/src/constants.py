USDT_TOKEN_ADDRESS = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDT_ADDED_BLOCKLIST_EVENT_ABI = """{
    "anonymous": false,
    "inputs": [
        {
            "indexed": false,
            "name": "_user",
            "type": "address"
        }
    ],
    "name": "AddedBlackList",
    "type": "event"
}"""
USDT_REMOVED_BLOCKLIST_EVENT_ABI = """{
    "anonymous": false,
    "inputs": [
        {
            "indexed": false,
            "name": "_user",
            "type": "address"
        }
    ],
    "name": "RemovedBlackList",
    "type": "event"
}"""

USDC_TOKEN_ADDRESS = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
USDC_BLOCKLISTED_EVENT_ABI = """{
    "anonymous": false,
    "inputs": [
        {
            "indexed": true,
            "internalType": "address",
            "name": "_account",
            "type": "address"
        }
    ],
    "name": "Blacklisted",
    "type": "event"
}"""
USDC_UNBLOCKLISTED_EVENT_ABI = """{
    "anonymous": false,
    "inputs": [
        {
            "indexed": true,
            "internalType": "address",
            "name": "_account",
            "type": "address"
        }
    ],
    "name": "UnBlacklisted",
    "type": "event"
}"""

CHAINALYSIS_SANCTIONS_LIST_ADDRESS = "0x40c57923924b5c5c5455c48d93317139addac8fb"
CHAINALYSIS_SANCTIONED_ADDRESS_ADDED_EVENT_ABI = """{
    "anonymous": false,
    "inputs": [
        {
            "indexed": false,
            "internalType": "address[]",
            "name": "addrs",
            "type": "address[]"
        }
    ],
    "name": "SanctionedAddressesAdded",
    "type": "event"
}
"""
CHAINALYSIS_SANCTIONED_ADDRESS_REMOVED_EVENT_ABI = """{
    "anonymous": false,
    "inputs": [
        {
            "indexed": false,
            "internalType": "address[]",
            "name": "addrs",
            "type": "address[]"
        }
    ],
    "name": "SanctionedAddressesRemoved",
    "type": "event"
}
"""
