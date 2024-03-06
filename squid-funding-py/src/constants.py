
EXPRESS_EXECUTE_WITH_TOKEN_FUNCTION_ABI = '{"inputs":[{"internalType":"bytes32","name":"commandId","type":"bytes32"},{"internalType":"string","name":"sourceChain","type":"string"},{"internalType":"string","name":"sourceAddress","type":"string"},{"internalType":"bytes","name":"payload","type":"bytes"},{"internalType":"string","name":"symbol","type":"string"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"expressExecuteWithToken","outputs":[],"stateMutability":"payable","type":"function"}'
WITHDRAWAL_EVENT_ABI = '{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Withdrawal","type":"event"}'
ERC20_TRANSFER_EVENT_ABI = '{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"}'

SWAP_EXACT_TOKENS_FOR_ETH_1 = '{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"components":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"bool","name":"stable","type":"bool"},{"internalType":"address","name":"factory","type":"address"}],"internalType":"struct IRouter.Route[]","name":"routes","type":"tuple[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"}'
SWAP_EXACT_TOKENS_FOR_ETH_1_SIG = '0xc6b7f1b6'
SWAP_EXACT_TOKENS_FOR_ETH_2 = '{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"}'
SWAP_EXACT_TOKENS_FOR_ETH_2_SIG = '0x18cbafe5'
SWAP_EXACT_TOKENS_FOR_ETH_3 = '{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"components":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"bool","name":"stable","type":"bool"}],"internalType":"struct Router.Route[]","name":"routes","type":"tuple[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"}'
SWAP_EXACT_TOKENS_FOR_ETH_3_SIG = '0x18a13086'
SWAP_EXACT_TOKENS_FOR_AVAX = '{"inputs": [{"internalType": "uint256","name": "amountIn","type": "uint256"},{"internalType": "uint256","name": "amountOutMin","type": "uint256"},{"internalType": "address[]","name": "path","type": "address[]"},{"internalType": "address","name": "to","type": "address"},{"internalType": "uint256","name": "deadline","type": "uint256"}],"name": "swapExactTokensForAVAX","outputs": [{"internalType": "uint256[]","name": "amounts","type": "uint256[]"}],"stateMutability": "nonpayable","type": "function"}'
SWAP_EXACT_TOKENS_FOR_AVAX_SIG = '0x676528d1'

SIGS_AND_ABIS = {
            SWAP_EXACT_TOKENS_FOR_ETH_1_SIG: SWAP_EXACT_TOKENS_FOR_ETH_1,
            SWAP_EXACT_TOKENS_FOR_ETH_2_SIG: SWAP_EXACT_TOKENS_FOR_ETH_2,
            SWAP_EXACT_TOKENS_FOR_ETH_3_SIG: SWAP_EXACT_TOKENS_FOR_ETH_3,
            SWAP_EXACT_TOKENS_FOR_AVAX_SIG: SWAP_EXACT_TOKENS_FOR_AVAX
        }

SQUID_TYPES = ["(uint8,address,uint256,bytes,bytes)[]", "address", "bytes32"] # (ISquidMulticall.Call[] calls, address refundRecipient, bytes32 salt)

ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

SQUID_ROUTER_ADDRESS = '0xce16f69375520ab01377ce7b88f5ba8c48f8d666'
SQUID_RELAYER = '0xe743a49f04f2f77eb2d3b753ae3ad599de8cea84'

WRAPPED_NATIVE_TOKEN_ADDRESSES = {
    1: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
    10: '0x4200000000000000000000000000000000000006',
    56: '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c',
    137: '0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270',
    250: '0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83',
    42161: '0x82af49447d8a07e3bd95bd0d56f35241523fbab1',
    43114: '0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7'
}

# At the time of deployment thresholds are set to ~$150
SQUID_THRESHOLDS = {
    1: 0.07,
    10: 0.07,
    56: 0.5,
    137: 190,
    250: 400,
    42161: 0.07,
    43114: 4
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
    56: "BSC",
    137: "MATIC",
    250: "FTM",
    42161: "ETH",
    43114: "AVAX"
}
