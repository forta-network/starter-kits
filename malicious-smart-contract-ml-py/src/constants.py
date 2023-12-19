CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.3  # threshold for model prediction
SAFE_CONTRACT_THRESHOLD = 0.1  # threshold for labelling safe contract
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91"
MODEL_THRESHOLD_DICT = {'default': 0.3, '1': 0.58, '56': .5, '137': .5, '250': .55, '43114': .6, '42161': .6, '10': .8}
