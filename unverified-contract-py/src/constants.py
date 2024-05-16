CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract
WAIT_TIME = 30  # how many minutes after contract creation we will wait for the creator to share source code on etherscan
CONCURRENT_SIZE = 5  # how many concurrent connections should be made.
RPC_ENDPOINTS = {1: ['https://rpc.ankr.com/eth', 'https://rpc.flashbots.net/', 'https://cloudflare-eth.com/',
                     'https://rpc.builder0x69.io', 'https://g.w.lavanet.xyz:443/gateway/eth/rpc-http/f7ee0000000000000000000000000000',
                     'https://endpoints.omniatech.io/v1/eth/mainnet/public', 'https://ethereum.blinklabs.xyz/', 'https://cloudflare-eth.com/v1/mainnet',
                     'https://eth.drpc.org/', 'https://rpc.propellerheads.xyz/eth', 'https://ethereum.blockpi.network/v1/rpc/public',
                     'https://ethereum.rpc.thirdweb.com/', 'https://mainnet.gateway.tenderly.co', 'https://rpc.builder0x69.io',
                     'https://gateway.tenderly.co/public/mainnet', 'https://api.stateless.solutions/ethereum/v1/demo',
                     'https://rpc.blocknative.com/boost', 'https://rpc.flashbots.net/fast']}
