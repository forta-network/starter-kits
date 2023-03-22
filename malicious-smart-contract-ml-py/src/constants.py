CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.5  # threshold for model prediction
SAFE_CONTRACT_THRESHOLD = 0.1  # threshold for labelling safe contract
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c"
