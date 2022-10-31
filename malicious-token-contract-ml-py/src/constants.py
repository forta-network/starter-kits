CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

MODEL_THRESHOLD = 0.5  # threshold for model prediction
BYTE_CODE_LENGTH_THRESHOLD = (
    60  # ignore contracts with byte code length below this threshold
)

TOKEN_TYPES = {"erc20", "erc721", "erc1155", "erc777"}
ERC20_SIGHASHES = {"a9059cbb", "dd62ed3e"}  # transfer and allowance sighashes
ERC721_SIGHASHES = {"42842e0e", "6352211e"}  # safeTransferFrom and ownerOf sighashes
ERC1155_SIGHASHES = {
    "2eb2c2d6",
    "4e1273f4",
}  # safeBatchTransferFrom and balanceOfBatch sighashes
ERC777_SIGHASHES = {"959b8c3f"}  # authorizeOperator sighashes
