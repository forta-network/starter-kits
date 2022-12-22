CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.5  # threshold for model prediction
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)

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
