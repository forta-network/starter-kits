CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.5  # threshold for model prediction
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)

# erc20 if it includes transfer , totalSupply, and allowance ('0xa9059cbb', '0x18160ddd', '0xdd62ed3e')
ERC20_SIGHASHES = {"0xa9059cbb", "0x18160ddd", "0xdd62ed3e"}

# erc721 if it includes safeTransferFrom, ownerOf, and isApprovedForAll ('0x42842e0e', '0x6352211e', '0xe985e9c5')
ERC721_SIGHASHES = {
    "0x42842e0e",
    "0x6352211e",
    "0xe985e9c5",
}  # safeTransferFrom and ownerOf sighashes

# erc1155 if it includes safeBatchTransferFrom, balanceOfBatch, and safeTransferFrom ('0x2eb2c2d6', '0x4e1273f4', '0xf242432a')
ERC1155_SIGHASHES = {"0x2eb2c2d6", "0x4e1273f4", "0xf242432a"}

# erc777 if it includes authorizeOperator and revokeOperator ('0x959b8c3f', '0xfad8b32a')
ERC777_SIGHASHES = {"0x959b8c3f", "0xfad8b32a"}

# 0x5c60da1b - implementation()
# 0x3659cfe6 - upgradeTo(address)
# 0x4f1ef286 - upgradeToAndCall(address,bytes)
# 0x8f283970 - changeAdmin(address)
PROXY_SIGHASHES = {"0x5c60da1b", "0x3659cfe6", "0x4f1ef286", "0x8f283970"}
