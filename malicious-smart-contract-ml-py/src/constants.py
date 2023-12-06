CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.2  # threshold for model prediction
SAFE_CONTRACT_THRESHOLD = 0.1  # threshold for labelling safe contract
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91"
