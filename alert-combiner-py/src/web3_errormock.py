class Web3ErrorMock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:    
    def get_code(self, address):
        raise Exception("unable to get contract code")  