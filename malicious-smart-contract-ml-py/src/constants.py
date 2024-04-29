CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.5  # threshold for model prediction
SAFE_CONTRACT_THRESHOLD = 0.1  # threshold for labelling safe contract
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0xf05b538e3f509118249e8e1b09e43bc0cd8f3d2bcd7a2a1c7f8181251fe49105"

RPC_ENDPOINTS = {1: ['https://rpc.ankr.com/eth', 'https://rpc.flashbots.net/', 'https://cloudflare-eth.com/',
                     'https://rpc.builder0x69.io', 'https://g.w.lavanet.xyz:443/gateway/eth/rpc-http/f7ee0000000000000000000000000000',
                     'https://endpoints.omniatech.io/v1/eth/mainnet/public', 'https://ethereum.blinklabs.xyz/', 'https://cloudflare-eth.com/v1/mainnet',
                     'https://eth.drpc.org/', 'https://rpc.propellerheads.xyz/eth', 'https://ethereum.blockpi.network/v1/rpc/public',
                     'https://ethereum.rpc.thirdweb.com/', 'https://mainnet.gateway.tenderly.co', 'https://rpc.builder0x69.io',
                     'https://gateway.tenderly.co/public/mainnet', 'https://api.stateless.solutions/ethereum/v1/demo',
                     'https://rpc.blocknative.com/boost', 'https://rpc.flashbots.net/fast']}
