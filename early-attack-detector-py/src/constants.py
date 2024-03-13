CONTRACT_SLOT_ANALYSIS_DEPTH = 10  # how many slots should be read to extract contract addresses from created contract

BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0xf60b23986fc15a8ff9bc78cc47daeb13a1bef4bfc3d867f3425b355f750866a7"

MODEL_PATH = 'deployed_models/NormalPre_eec.joblib'
MODEL_THRESHOLD_ETH = .52
MODEL_THRESHOLD_ETH_PRECISION = .69
MODEL_THRESHOLD_DEFAULT = .57
MODEL_THRESHOLD_DEFAULT_PRECISION = 1

MODEL_INFO_THRESHOLD = 0.5

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