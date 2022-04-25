USDT_TOKEN_ADDRESS = "0xdac17f958d2ee523a2206206994597c13d831ec7"
ADDED_BLACKLIST_EVENT_ABI = """{
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
REMOVED_BLACKLIST_EVENT_ABI = """{
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
BLACKLISTED_EVENT_ABI = """{
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
UNBLACKLISTED_EVENT_ABI = """{
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
SANCTIONED_ADDRESS_ADDED_EVENT_ABI = """{
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
SANCTIONED_ADDRESS_REMOVED_EVENT_ABI = """{
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
