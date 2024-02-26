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

FUNDING_BOTS = [
        '0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400',  # funding tornado cash
        '0x025251bd9b67b18804249a61a19f8dd45e3dd30caba295ed2cdc9392039f6272',  # funding union chain
        '0xd2a25c368501ec7f9cd1219858c8a53cc4da7bd64c43633658a90b54bfcc595a',  # funding railgun
        '0x2d3bb89e9cecc0024d8ae1a9c93ca42664472cb074cc200fa2c0f77f2be34bf3',  # funding fixed float
        '0xa5a23e3fd7a5401db47008329061bb9dca48fc0199151e043d93376d31adb40d',  # funding squid
        '0xf2ee3554a13ee126dae179918e89010afc1bfc1ffabd3a381b529632ebf7497a',  # funding thorchain
        '0x29daabf74506f2aa4feb93fa8ec0f4ac61c4e9ba3f3190072bc680bc70e71bd7',  # funding eXch
        '0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e',  # funding ChangeNow
    ]