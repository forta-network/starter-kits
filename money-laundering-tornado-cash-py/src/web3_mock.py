EOA_ADDRESS = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4'


class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    chain_id = 1

    def __init__(self):
        self.contract = ContractMock()


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
