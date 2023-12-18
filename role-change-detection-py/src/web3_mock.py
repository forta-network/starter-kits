from web3 import Web3
from hexbytes import HexBytes

NEW_EOA = '0x49A9deCA3DcA86aB3A029C2ed629EC8477009Fee'
OLD_EOA = '0x4e5b2E1Dc63f6B91cb6cD759936495434c7E0000'
VERIFIED_CONTRACT = '0x2320A28f52334d62622cc2EaFa15DE55F9987eD0'

MOCK_TX_HASH_TO_INPUT_MAPPING = {
    "0x30a332902920cb6886281f6d28abfa5775559647eb7288e7cc00763fe4427f7b": "0x124cc077",
    "0x8fc91a50a2614d323864655c2473ec19e58cb356a9f1d391888c472476c749f7": "0xa9059cbb"
}

MOCK_TX_INPUT_TO_DECODED_INPUT_MAPPING = {
    "0x124cc077": ["(<Function setMetadataManager(address)>, {'newMetadataManager': '0x5C95123b1c8d9D8639197C81a829793B469A9f32'})"],
    "0xa9059cbb" : ["(<Function transfer(address,uint256)>, {'_to': '0x28C6c06298d514Db089934071355E5743bf21d60', '_value': 1000000000000000000})"]
}


class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock(address=None, abi=None)

    chain_id = 1

    def get_code(self, address):
        if address == Web3.toChecksumAddress(VERIFIED_CONTRACT):
            return HexBytes(
                '0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea26469706673582212209a159a4f3847890f10bfb87871a61eba91c5dbf5ee3cf6398207e292eee22a1664736f6c63430008070033'
            )
        elif address == Web3.toChecksumAddress(NEW_EOA) or address == Web3.toChecksumAddress(OLD_EOA):
            return HexBytes('0x')
     
        return HexBytes('0x')

    def get_transaction(self, transaction_hash):
        transaction = TransactionMock(MOCK_TX_HASH_TO_INPUT_MAPPING[transaction_hash])
        return transaction


class TransactionMock:
    def __init__(self, data):
        self.input = data


class ContractMock:
    def __init__(self, address, abi):
        self.functions = FunctionsMock()

    def __call__(self, address, *args, **kwargs):
        return self

    def decode_function_input(self, transaction_input):
        print(transaction_input)
        print(MOCK_TX_INPUT_TO_DECODED_INPUT_MAPPING[transaction_input])
        return MOCK_TX_INPUT_TO_DECODED_INPUT_MAPPING[transaction_input]


class FunctionsMock:
    def __init__(self):
        self.return_value = None

    def call(self, *_, **__):
        return self.return_value