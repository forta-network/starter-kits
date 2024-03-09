CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.5  # threshold for model prediction
SAFE_CONTRACT_THRESHOLD = 0.1  # threshold for labelling safe contract
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0xf05b538e3f509118249e8e1b09e43bc0cd8f3d2bcd7a2a1c7f8181251fe49105"
