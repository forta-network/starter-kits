import { Market } from '../types';


export type CurrencyAddress =
    | '0x0000000000000000000000000000000000000000'
    | '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
    | '0x6b175474e89094c44da98b954eedeac495271d0f'
    | '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
    | '0x4d224452801aced8b2f0aebe155379bb5d594381'
    | '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c'
    | '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619';

export type Currency = {
    [key in CurrencyAddress]: {
        name: string;
        decimals: number;
    };
};

const currencies: Currency = {
    // ETH
    '0x0000000000000000000000000000000000000000': {
        name: 'ETH',
        decimals: 18
    },
    // ETH WETH
    '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': {
        name: 'WETH',
        decimals: 18
    },
    // DAI
    '0x6b175474e89094c44da98b954eedeac495271d0f': {
        name: 'DAI',
        decimals: 18
    },
    // USDC
    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': {
        name: 'USDC',
        decimals: 6
    },
    // APE
    '0x4d224452801aced8b2f0aebe155379bb5d594381': {
        name: 'APE',
        decimals: 18
    },
    // BNB
    '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c': {
        name: 'BNB',
        decimals: 18
    },
    // Poly WETH
    '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619': {
        name: 'WETH',
        decimals: 18
    },
};

const markets: { [key: string]: Market } = {
    // Sudoswap Pair Router Address
    '0x2b2e8cda09bba9660dca5cb6233787738ad68329': {
        name: 'sudoswap',
        displayName: 'Sudoswap',
        contract: '0x2b2e8cda09bba9660dca5cb6233787738ad68329',
        color: 11975166,
        site: 'https://opensea.io/assets/',
        accountPage: 'https://opensea.io/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1542272594686054401/vOi42ixp_400x400.jpg',
        topics: ['0x0']
    },
    // NFT Trader Gnosis Safe Address
    '0x83db44123e76503203fdf83d2be58be60c15b894': {
        name: 'nfttrader',
        displayName: 'NFT Trader 🔄',
        contract: '0x83db44123e76503203fdf83d2be58be60c15b894',
        color: 14417664,
        site: 'https://etherscan.io/tx/',
        accountPage: 'https://opensea.io/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1538537469779623937/pHkL_wiw_400x400.png',
        topics: ['0x0']
    },
    // BlurSwap Contract Address
    '0x39da41747a83aee658334415666f3ef92dd0d541': {
        name: 'blurswap',
        displayName: 'Blur Swap 🟠',
        contract: '0x39da41747a83aee658334415666f3ef92dd0d541',
        color: 16742912,
        site: 'https://opensea.io/assets/',
        accountPage: 'https://opensea.io/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1518705644450291713/X2FLVDdn_400x400.jpg',
        topics: ['0x0']
    },
    // GemSwap Contract Address
    '0x83c8f28c26bf6aaca652df1dbbe0e1b56f8baba2': {
        name: 'gem',
        displayName: 'Gem 💎',
        contract: '0x83c8f28c26bf6aaca652df1dbbe0e1b56f8baba2',
        color: 15760029,
        site: 'https://www.gem.xyz/asset/',
        accountPage: 'https://www.gem.xyz/profile/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1469735318488293380/AuOdfwvH_400x400.jpg',
        topics: ['0x0']
    },
    // Gem Single Contract Checkout 1 Address
    '0x0000000031f7382a812c64b604da4fc520afef4b': {
        name: 'gem',
        displayName: 'Gem 💎',
        contract: '0x0000000031f7382a812c64b604da4fc520afef4b',
        color: 15760029,
        site: 'https://www.gem.xyz/asset/',
        accountPage: 'https://www.gem.xyz/profile/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1469735318488293380/AuOdfwvH_400x400.jpg',
        topics: ['0x0']
    },
    // Gem Single Contract Checkout 2 Address
    '0x0000000035634b55f3d99b071b5a354f48e10bef': {
        name: 'gem',
        displayName: 'Gem 💎',
        contract: '0x0000000035634b55f3d99b071b5a354f48e10bef',
        color: 15760029,
        site: 'https://www.gem.xyz/asset/',
        accountPage: 'https://www.gem.xyz/profile/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1469735318488293380/AuOdfwvH_400x400.jpg',
        topics: ['0x0']
    },
    // Gem Single Contract Checkout 3 Address
    '0x00000000a50bb64b4bbeceb18715748dface08af': {
        name: 'gem',
        displayName: 'Gem 💎',
        contract: '0x00000000a50bb64b4bbeceb18715748dface08af',
        color: 15760029,
        site: 'https://www.gem.xyz/asset/',
        accountPage: 'https://www.gem.xyz/profile/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1469735318488293380/AuOdfwvH_400x400.jpg',
        topics: ['0x0']
    },
    // Gem Single Contract Checkout 4 Address
    '0xae9c73fd0fd237c1c6f66fe009d24ce969e98704': {
        name: 'gem',
        displayName: 'Gem 💎',
        contract: '0xae9c73fd0fd237c1c6f66fe009d24ce969e98704',
        color: 15760029,
        site: 'https://www.gem.xyz/asset/',
        accountPage: 'https://www.gem.xyz/profile/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1469735318488293380/AuOdfwvH_400x400.jpg',
        topics: ['0x0']
    },
    // GenieSwap Contract Address
    '0x0a267cf51ef038fc00e71801f5a524aec06e4f07': {
        name: 'genie',
        displayName: 'Genie 🧞‍♂️',
        contract: '0x0a267cf51ef038fc00e71801f5a524aec06e4f07',
        color: 16777215,
        site: 'https://opensea.io/assets/',
        accountPage: 'https://opensea.io/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1486044157017788419/cqdhpZBX_400x400.png',
        topics: ['0x0']
    },
    // X2Y2 Contract Address
    '0x74312363e45dcaba76c59ec49a7aa8a65a67eed3': {
        name: 'x2y2',
        displayName: 'X2Y2 ⭕️',
        contract: '0x74312363e45dcaba76c59ec49a7aa8a65a67eed3',
        color: 57599,
        site: 'https://x2y2.io/eth/',
        accountPage: 'https://x2y2.io/user/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1610305658695618560/4pLyofR7_400x400.png',
        topics: [
            '0x3cbb63f144840e5b1b0a38a7c19211d2e89de4d7c5faf8b2d3c1776c302d1d33'
        ]
    },
    // LooksRareExchange Contract Address
    '0x0000000000e655fae4d56241588680f86e3b2377': {
        name: 'looksrare',
        displayName: 'LooksRare 👀💎',
        contract: '0x0000000000e655fae4d56241588680f86e3b2377',
        color: 844901,
        site: 'https://looksrare.org/collections/',
        accountPage: 'https://looksrare.org/accounts/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1607554816049545216/WbL9E92K_400x400.jpg',
        topics: [
            '0x95fb6205e23ff6bda16a2d1dba56b9ad7c783f67c96fa149785052f47696f2be',
            '0x68cd251d4d267c6e2034ff0088b990352b97b2002c0476587d0c4da889c11330',
            '0x3ee3de4684413690dee6fff1a0a4f92916a1b97d1c5a83cdf24671844306b2e3',
            '0x9aaa45d6db2ef74ead0751ea9113263d1dec1b50cea05f0ca2002cb8063564a4'
        ]
    },
    // Opensea Seaport Protocol Contract Address
    '0x00000000006c3852cbef3e08e8df289169ede581': {
        name: 'opensea',
        displayName: 'Opensea 🌊',
        contract: '0x00000000006c3852cbef3e08e8df289169ede581',
        color: 2130402,
        site: 'https://opensea.io/assets/',
        accountPage: 'https://opensea.io/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1544105652330631168/ZuvjfGkT_400x400.png',
        topics: [
            '0x9d9af8e38d66c62e2c12f0225249fd9d721c54b83f48d9352c97c6cacdcb6f31'
        ]
    },
    // Seaport 1.4
    '0x00000000000001ad428e4906ae43d8f9852d0dd6': {
        name: 'opensea',
        displayName: 'Opensea 🌊',
        contract: '0x00000000000001ad428e4906ae43d8f9852d0dd6',
        color: 2130402,
        site: 'https://opensea.io/assets/',
        accountPage: 'https://opensea.io/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1544105652330631168/ZuvjfGkT_400x400.png',
        topics: [
            '0x9d9af8e38d66c62e2c12f0225249fd9d721c54b83f48d9352c97c6cacdcb6f31'
        ]
    },
    // Seaport 1.5
    '0x00000000000000adc04c56bf30ac9d3c0aaf14dc': {
        name: 'opensea',
        displayName: 'Opensea 🌊',
        contract: '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
        color: 2130402,
        site: 'https://opensea.io/assets/',
        accountPage: 'https://opensea.io/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1544105652330631168/ZuvjfGkT_400x400.png',
        topics: [
            '0x9d9af8e38d66c62e2c12f0225249fd9d721c54b83f48d9352c97c6cacdcb6f31'
        ]
    },
    '0x000000000000ad05ccc4f10045630fb830b95127': {
        name: 'blur',
        displayName: 'Blur 🟠',
        contract: '0x000000000000ad05ccc4f10045630fb830b95127',
        color: 16742912,
        site: 'https://opensea.io/assets/',
        accountPage: 'https://opensea.io/',
        iconURL:
            'https://pbs.twimg.com/profile_images/1518705644450291713/X2FLVDdn_400x400.jpg',
        topics: [
            '0x61cbb2a3dee0b6064c2e681aadd61677fb4ef319f0b547508d495626f5a62f64'
        ]
    }
};

export { markets, currencies };
