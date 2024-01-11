CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.3  # threshold for model prediction
SAFE_CONTRACT_THRESHOLD = 0.1  # threshold for labelling safe contract
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91"
MODEL_THRESHOLD_DICT = {'default': 0.3, '1': 0.58, '56': .5, '137': .7, '250': .8, '43114': .8, '42161': .8, '10': .5}
# Threshold information
# chain_idc     hain_name       voting_threshold        support_threshold    Marked with x is the model deployed
# 1             eth             0.58    x               -
# 56            bsc             0.5     x               -
# 137           polygon         0.5                     .7      x
# 250           fantom          0.55                    .8      x
# 43114         avalanche       0.6                     .8      x
# 42161         arbitrum        0.6                     .8      x
# 10            optimism        0.8                     .5      x
