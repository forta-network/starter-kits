STABLECOIN_CONTRACTS = {
    1: [
        '0xdac17f958d2ee523a2206206994597c13d831ec7',
        '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
        '0x6b175474e89094c44da98b954eedeac495271d0f',
        '0x0000000000085d4780B73119b644AE5ecd22b376'
    ],
    56: [
        '0x55d398326f99059ff775485246999027b3197955',
        '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d',
        '0x8965349fb649a33a30cbfda057d8ec2c48abe2a2',
        '0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3',
        '0xe9e7cea3dedca5984780bafc599bd69add087d56'
    ],
    137: [
        '0x2791bca1f2de4661ed88a30c99a7a9449aa84174',
        '0xdab529f40e671a1d4bf91361c21bf9f0c9712ab7',
        '0x8f3cf7ad23cd3cadbd9735aff958023239c6a063',
        '0xc2132d05d31c914a87c6611c10748aeb04b58e8f'
    ],
    42161: [
        '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9',
        '0xff970a61a04b1ca14834a43f5de4533ebddb5cc8',
        '0xda10009cbd5d07dd0cecc66161fc93d7c9000da1',
        '0x4d15a3a2286d883af0aa1b3f21367843fac63e07'
    ],
    10: [
        '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58',
        '0x7f5c764cbc14f9669b88837ca1490cca17c31607',
        '0xda10009cbd5d07dd0cecc66161fc93d7c9000da1'
    ],
    250: [
        '0x04068da6c83afcfa0e13ba15a6696662335d5b75',
        '0x8d11ec38a3eb5e956b052f67da8bdc9bef8abf3e',
        '0x9879abdea01a879644185341f7af7d8343556b7a'
    ],
    43114: [
        '0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7',
        '0xc7198437980c041c805a1edcba50c1ce5db95118',
        '0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e',
        '0xa7d7079b0fead91f3e65f86e8915cb59c1a4c664',
        '0x19860ccb0a68fd4213ab9d8266f7bbf05a8dde98',
        '0x9c9e5fd8bbc25984b178fdce6117defa39d2db39',
        '0xd586e7f844cea2f87f50152665bcbc2c279d8d70'
    ]
}

BASE_TOKENS = [
    '0x0000000000000000000000000000000000001010', # MATIC on Polygon
    '0x4200000000000000000000000000000000000042', # OP on Optimism
    '0x658b0c7613e890ee50b8c4bc6a3f41ef411208ad' # FETH on Fantom
]

# ABIs for decoding relevant log events
TRANSFER_EVENT_ABI = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}'
APPROVAL_EVENT_ABI = '{"name":"Approval","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}'

# ABI for symbol function
SYMBOL_CALL_ABI = [
    {
      "constant": True,
      "inputs": [],
      "name": "symbol",
      "outputs": [
          {"name": "",
            "type": "string"
          }
      ],
      "payable": False,
      "stateMutability": "view",
      "type": "function"
    }
]

# Used to detect fraudulent tokens, after checking their symbol().call() reponse
OFFICIAL_SYMBOLS = {
    1: ['USDT', 'USDC', 'ETH', 'DAI'],
    56: ['USDT', 'USDC', 'BSC', 'anyUSDC', 'DAI', 'BUSD'],
    137: ['USDT', 'USDC', 'MATIC', 'BUSD', 'DAI'],
    42161: ['USDT', 'USDC', 'DAI', 'TUSD'],
    10: ['USDT', 'USDC', 'DAI', 'OP'],
    250: ['TUSD', 'USDC', 'DAI', 'FETH'],
    43114: ['USDT.e', 'USDt', 'USDC', 'USDC.e', 'BUSD.e', 'BUSD', 'DAI.e', 'AVAX']
}

CHAIN_ORDINAL_SYMBOL_MAP = {
    1: [
        [85, 83, 68, 84], # USDT
        [85, 83, 68, 1058], # USDТ -> Cyrillic T
        [85, 83, 68, 67], # USDC
        [85, 83, 68, 1057], # USDС -> Cyrillic C
        [69, 84, 72], # ETH
        [1045, 84, 72], # ЕTH -> Cyrillic E
        [68, 65, 73], # DAI
        [68, 1040, 73] # DАI -> Cyrillic A
    ]
}