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
