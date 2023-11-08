from hexbytes import HexBytes

NEW_EOA = '0x49A9deCA3DcA86aB3A029C2ed629EC8477009Fee'
OLD_EOA = '0x4e5b2E1Dc63f6B91cb6cD759936495434c7E0000'
CONTRACT = '0x2320A28f52334d62622cc2EaFa15DE55F9987eD0'

MOCK_TX_HASH_LOGS_MAPPING = {
    "0xpositive_zero": {'logs': [
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x0000000000000000000000000000000000000000000000000000000000000000',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
        ]
    },
    "0xnegative_zero": {'logs':[
            {
                'address': NEW_EOA,
                'data': '0x0000000000000000000000000000000000000000000000000000000000100000',
                'topics':[HexBytes("0x0000000000000000000000003e02bc40db6c236d12f07a2e78db4e08f9aa4561")]
            },
            {
                'address': NEW_EOA,
                'data': '0x0000000000000000000000000000000000000000000000000000000000100000',
                'topics':[HexBytes("0x0000000000000000000000003e02bc40db6c236d12f07a2e78db4e08f9aa4561")]
            }
        ]
    },
    "0xpositive_low": {'logs': [
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000186a0',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000186a0',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x0000000000000000000000000000000000000000000000000000000000019a28',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x0000000000000000000000000000000000000000000000000000000000019a28',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f0',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f0',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f1',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f1',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
        ]
    },
    "0xnegative_low": { "logs": [
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000549f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            }
        ]
    },
    "0xpositive_fake_token": { "logs": [
            {
                'address': '0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xCf117403474eEaC230DaCcB3b54c0dABeB94Ae22',
                'data': '0x00000000000000000000000000000000000000000000000000000000000549f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xCf117403474eEaC230DaCcB3b54c0dABeB94Ae22',
                'data': '0x00000000000000000000000000000000000000000000000000000000000549f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xCf117403474eEaC230DaCcB3b54c0dABeB94Ae22',
                'data': '0x00000000000000000000000000000000000000000000000000000000000549f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xCf117403474eEaC230DaCcB3b54c0dABeB94Ae22',
                'data': '0x00000000000000000000000000000000000000000000000000000000000549f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xCf117403474eEaC230DaCcB3b54c0dABeB94Ae22',
                'data': '0x00000000000000000000000000000000000000000000000000000000000549f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            }
        ]
    },
    "0xnegative_fake_token": { "logs": [
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000249f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            },
            {
                'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                'data': '0x00000000000000000000000000000000000000000000000000000000000549f2',
                'topics':[HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")]
            }
        ]
    },
    "0x_token_mint": {  "logs": [
            {
                'address': '0x4f06229a42e344b361D8dc9cA58D73e2597a9f1F',
                'data': "0x",
                'topics': [
                    HexBytes('0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'),
                    HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000'),
                    HexBytes('0x000000000000000000000000302f442c5aa90177684b551883fc32b151178e7b'),
                    HexBytes('0x0000000000000000000000000000000000000000000000000000000000000006')
                ]
            }
        ]
    }
}