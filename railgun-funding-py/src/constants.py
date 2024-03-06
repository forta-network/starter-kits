
RELAY_FUNCTION_ABI = '{"inputs":[{"components":[{"components":[{"components":[{"internalType":"uint256","name":"x","type":"uint256"},{"internalType":"uint256","name":"y","type":"uint256"}],"internalType":"struct G1Point","name":"a","type":"tuple"},{"components":[{"internalType":"uint256[2]","name":"x","type":"uint256[2]"},{"internalType":"uint256[2]","name":"y","type":"uint256[2]"}],"internalType":"struct G2Point","name":"b","type":"tuple"},{"components":[{"internalType":"uint256","name":"x","type":"uint256"},{"internalType":"uint256","name":"y","type":"uint256"}],"internalType":"struct G1Point","name":"c","type":"tuple"}],"internalType":"struct SnarkProof","name":"proof","type":"tuple"},{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"internalType":"bytes32[]","name":"nullifiers","type":"bytes32[]"},{"internalType":"bytes32[]","name":"commitments","type":"bytes32[]"},{"components":[{"internalType":"uint16","name":"treeNumber","type":"uint16"},{"internalType":"uint72","name":"minGasPrice","type":"uint72"},{"internalType":"enum UnshieldType","name":"unshield","type":"uint8"},{"internalType":"uint64","name":"chainID","type":"uint64"},{"internalType":"address","name":"adaptContract","type":"address"},{"internalType":"bytes32","name":"adaptParams","type":"bytes32"},{"components":[{"internalType":"bytes32[4]","name":"ciphertext","type":"bytes32[4]"},{"internalType":"bytes32","name":"blindedSenderViewingKey","type":"bytes32"},{"internalType":"bytes32","name":"blindedReceiverViewingKey","type":"bytes32"},{"internalType":"bytes","name":"annotationData","type":"bytes"},{"internalType":"bytes","name":"memo","type":"bytes"}],"internalType":"struct CommitmentCiphertext[]","name":"commitmentCiphertext","type":"tuple[]"}],"internalType":"struct BoundParams","name":"boundParams","type":"tuple"},{"components":[{"internalType":"bytes32","name":"npk","type":"bytes32"},{"components":[{"internalType":"enum TokenType","name":"tokenType","type":"uint8"},{"internalType":"address","name":"tokenAddress","type":"address"},{"internalType":"uint256","name":"tokenSubID","type":"uint256"}],"internalType":"struct TokenData","name":"token","type":"tuple"},{"internalType":"uint120","name":"value","type":"uint120"}],"internalType":"struct CommitmentPreimage","name":"unshieldPreimage","type":"tuple"}],"internalType":"struct Transaction[]","name":"_transactions","type":"tuple[]"},{"components":[{"internalType":"bytes31","name":"random","type":"bytes31"},{"internalType":"bool","name":"requireSuccess","type":"bool"},{"internalType":"uint256","name":"minGasLimit","type":"uint256"},{"components":[{"internalType":"address","name":"to","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"uint256","name":"value","type":"uint256"}],"internalType":"struct RelayAdapt.Call[]","name":"calls","type":"tuple[]"}],"internalType":"struct RelayAdapt.ActionData","name":"_actionData","type":"tuple"}],"name":"relay","outputs":[],"stateMutability":"payable","type":"function"}'
TRANSFER_FUNCTION_ABI = '{"inputs":[{"components":[{"components":[{"internalType":"enum TokenType","name":"tokenType","type":"uint8"},{"internalType":"address","name":"tokenAddress","type":"address"},{"internalType":"uint256","name":"tokenSubID","type":"uint256"}],"internalType":"struct TokenData","name":"token","type":"tuple"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"internalType":"struct RelayAdapt.TokenTransfer[]","name":"_transfers","type":"tuple[]"}],"name":"transfer","outputs":[],"stateMutability":"nonpayable","type":"function"}'
WITHDRAWAL_EVENT_ABI = '{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Withdrawal","type":"event"}'
ERC20_TRANSFER_EVENT_ABI = '{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"}'
RAILGUN_TRANSFER_FUNCTION_SIG = 'c2e9ffd8'

ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

RAILGUN_ADDRESS = {
    1: '0x4025ee6512dbbda97049bcf5aa5d38c54af6be8a',
    56: '0x741936fb83ddf324636d3048b3e6bc800b8d9e12',
    137: '0xc7ffa542736321a3dd69246d73987566a5486968',
    42161: '0x5ad95c537b002770a39dea342c4bb2b68b1497aa',
}

WRAPPED_NATIVE_TOKEN_ADDRESSES = {
    1: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
    56: '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c',
    137: '0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270',
    42161: '0x82af49447d8a07e3bd95bd0d56f35241523fbab1'
}

# At the time of deployment thresholds are set to ~$150
RAILGUN_THRESHOLDS = {
    1: 0.07,
    56: 0.5,
    137: 190,
    42161: 0.07
}

PROTOCOLS = {
    1: 'ethereum',
    56: 'binance smart chain',
    137: 'polygon',
    42161: 'arbitrum'
}

CURRENCIES = {
    1: "ETH",
    56: "BSC",
    137: "MATIC",
    42161: "ETH"
}
