CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)
MASK = "0xffffffffffffffffffffffffffffffffffffffff"
BOT_ID = "0xf60b23986fc15a8ff9bc78cc47daeb13a1bef4bfc3d867f3425b355f750866a7"
MODEL_THRESHOLD_ETH = .5
MODEL_THRESHOLD_ETH_PRECISION = .6
MODEL_THRESHOLD_DEFAULT = .53

FUNDING_BOTS = [
        '0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400',  # funding tornado cash
        '0x025251bd9b67b18804249a61a19f8dd45e3dd30caba295ed2cdc9392039f6272',  # funding union chain
        '0xd2a25c368501ec7f9cd1219858c8a53cc4da7bd64c43633658a90b54bfcc595a',  # funding railgun
        '0x2d3bb89e9cecc0024d8ae1a9c93ca42664472cb074cc200fa2c0f77f2be34bf3',  # funding fixed float
        '0xa5a23e3fd7a5401db47008329061bb9dca48fc0199151e043d93376d31adb40d',  # funding squid
    ]