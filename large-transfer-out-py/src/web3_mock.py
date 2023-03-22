from web3 import Web3


ADDRESS_WITH_LARGE_BALANCE = '0x49A9deCA3DcA86aB3A029C2ed629EC8477009Fee'
ADDRESS_WITHOUT_LARGE_BALANCE = '0x2320A28f52334d62622cc2EaFa15DE55F9987eD9'
CURRENT_BLOCK = 15489547
OLDER_CURRENT_BLOCK = 15483790


class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock()

    chainId = 1

    def get_balance(self, address, block_identifier):
        if address == Web3.toChecksumAddress(ADDRESS_WITH_LARGE_BALANCE) and block_identifier <= OLDER_CURRENT_BLOCK:
            return 50000000000000000000
        if address == Web3.toChecksumAddress(ADDRESS_WITH_LARGE_BALANCE) and block_identifier <= CURRENT_BLOCK:
            return 50000000000000000000
        if address == Web3.toChecksumAddress(ADDRESS_WITHOUT_LARGE_BALANCE) and block_identifier <= OLDER_CURRENT_BLOCK:
            return 9000000000000000000
        if address == Web3.toChecksumAddress(ADDRESS_WITHOUT_LARGE_BALANCE) and block_identifier <= CURRENT_BLOCK:
            return 50000000000000000000


class ContractMock:
    def __init__(self):
        self.functions = FunctionsMock()

    def __call__(self, address, *args, **kwargs):
        return self


class FunctionsMock:
    def __init__(self):
        self.return_value = None

    def call(self, *_, **__):
        return self.return_value
