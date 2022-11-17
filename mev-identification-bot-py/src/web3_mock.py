from hexbytes import HexBytes

CONTRACT_ADDRESS_1 = "0x00000000000000000000000000000000000000AB"
CONTRACT_ADDRESS_2 = "0x00000000000000000000000000000000000000BB"
CONTRACT_ADDRESS_3 = "0x00000000000000000000000000000000000000CB"
CONTRACT_ADDRESS_4 = "0x00000000000000000000000000000000000000DB"

class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    chain_id = 1

    def __init__(self):
        self.contract = ContractMock()

    def get_code(self, address):
        if address.lower() == CONTRACT_ADDRESS_1.lower() or address.lower() == CONTRACT_ADDRESS_2.lower() or address.lower() == CONTRACT_ADDRESS_3.lower() or address.lower() == CONTRACT_ADDRESS_4.lower():
            return HexBytes('0xFFFF')
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

