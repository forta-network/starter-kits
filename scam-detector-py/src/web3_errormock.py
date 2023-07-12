from hexbytes import HexBytes

class Web3ErrorMock:
    def __init__(self):
        self.eth = EthMock()



class EthMock:
    def __init__(self):
        self.contract = ContractMock()

    def get_transaction_count(self, address):
        raise BaseException("unable to get tx account")


    def chain_id(self):
        return 1

    
    def get_code(self, address):
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
