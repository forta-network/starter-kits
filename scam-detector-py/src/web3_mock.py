from hexbytes import HexBytes

EOA_ADDRESS_SMALL_TX = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4'  # small tx count
EOA_ADDRESS_LARGE_TX = '0xdec08cb92a506B88411da9Ba290f3694BE223c26'  # large tx count
CONTRACT = '0x2320A28f52334d62622cc2EaFa15DE55F9987eD9'




class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock()

    def get_transaction_count(self, address):
        if address == EOA_ADDRESS_SMALL_TX:
            return 1999
        elif address == EOA_ADDRESS_LARGE_TX:
            return 2001
        return 0

    def chain_id(self):
        return 1

    def get_transaction(self, hash):
        if hash == '0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a026aa':
            return {'to': '0x91C1B58F24F5901276b1F2CfD197a5B73e31F96E'}
        else:
            return {'to': '0x21e13f16838e2fe78056f5fd50251ffd6e7098b4'}

    def get_code(self, address):
        if address == EOA_ADDRESS_SMALL_TX:
            return HexBytes('0x')
        elif address == CONTRACT:
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
