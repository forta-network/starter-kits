CONTRACT_SLOT_ANALYSIS_DEPTH = 10  # how many slots should be read to extract contract addresses from created contract

BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0xf60b23986fc15a8ff9bc78cc47daeb13a1bef4bfc3d867f3425b355f750866a7"

MODEL_PATH = 'deployed_models/NormalPre_eec.joblib'
HIGH_PRECISION_MODEL_PATH = 'deployed_models/NormalPre_newdata_brcf.joblib'
MODEL_THRESHOLD_ETH = .52
MODEL_THRESHOLD_ETH_PRECISION = .98
MODEL_THRESHOLD_DEFAULT = .57
MODEL_THRESHOLD_DEFAULT_PRECISION = .99

MODEL_INFO_THRESHOLD = 0.5

FUNDING_BOTS = [
        '0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400',  # funding tornado cash
        '0xd2a25c368501ec7f9cd1219858c8a53cc4da7bd64c43633658a90b54bfcc595a',  # funding railgun
        '0x2d3bb89e9cecc0024d8ae1a9c93ca42664472cb074cc200fa2c0f77f2be34bf3',  # funding fixed float
        '0xf2ee3554a13ee126dae179918e89010afc1bfc1ffabd3a381b529632ebf7497a',  # funding thorchain
        '0x29daabf74506f2aa4feb93fa8ec0f4ac61c4e9ba3f3190072bc680bc70e71bd7',  # funding eXch
        '0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e',  # funding ChangeNow
        '0x90596fcef715e22cc073fdc7018039e7af742276dda1baed03032411480c65fd',  # funding with hops
        '0xf1c75d2674ecf85be5e95b4959284ce8ed758885ddd7be64923c893ceff49efe',  # SWFT swap
    ]
FUNDING_TIME = 1  # How many days in the past to look for labels

# For the following funding bots, we want to look deeper into the past
EXTRA_TIME_BOTS = [
    '0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400'  # funding tornado cash
]
EXTRA_TIME_DAYS = 180

ONE_DAY = 60 * 60 * 24
THREE_SECOND_BLOCK_TIME = 3
ETH_BLOCK_TIME = 12
ETH_BLOCKS_IN_ONE_DAY = ONE_DAY / ETH_BLOCK_TIME
# Amount of blocks in a day for faster chains
# Using 3 second block times as the average
THREE_SECOND_BLOCKS_IN_ONE_DAY = ONE_DAY / THREE_SECOND_BLOCK_TIME