CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.5  # threshold for model prediction
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)

TOKEN_TYPES = {"erc20", "erc721", "erc1155", "erc777"}
ERC20_SIGHASHES = {"a9059cbb", "dd62ed3e"}  # transfer and allowance sighashes
ERC721_SIGHASHES = {"42842e0e", "6352211e"}  # safeTransferFrom and ownerOf sighashes
ERC1155_SIGHASHES = {
    "2eb2c2d6",
    "4e1273f4",
}  # safeBatchTransferFrom and balanceOfBatch sighashes
ERC777_SIGHASHES = {"959b8c3f"}  # authorizeOperator sighashes

CHAIN_ID_METADATA_MAPPING = {
    1: (
        "ethereum",
        172,  # alert_count
        32_713,  # contract deployment
    ),  # alert_count = avg of last 24 hrs of Nov 14, 2022.
    137: ("polygon", 194, 6_681),
    56: ("binance", 182, 299_458),
    43114: ("avalanche", 23, 432),
    42161: ("arbitrum", 302, 9_800),
    10: ("optimism", 15, 1_651),
    250: ("fantom", 7, 345_486),
}

LUABASE_SUPPORTED_CHAINS = {1, 137, 43114, 250}
