EOA_ADDRESS = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb8'
EOA_ADDRESS_2 = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb7'
CONTRACT = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb9'.lower()

from hexbytes import HexBytes

class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock()

    def chain_id(self):
        return 1
    
    def get_code(self, address):
        if address.lower() == EOA_ADDRESS:
            return HexBytes('0x')
        elif address.lower() == CONTRACT:
            return HexBytes('0x0000000000000000000000000000000000000000000000000000000000000005')
        else:
            return HexBytes('0x')


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
