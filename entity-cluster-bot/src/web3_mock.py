from hexbytes import HexBytes

EOA_ADDRESS_OLD = '0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4'  
EOA_ADDRESS_NEW = '0xdec08cb92a506B88411da9Ba290f3694BE223c26'  

EOA_ADDRESS_SMALL_TX = '0x6ADEBC8729d03c3dFAAD6660B746754Bc475E13d'  
EOA_ADDRESS_LARGE_TX = '0x942dFB0C7e87fb5f07e25EC7Ff805e7F973cF929'  


EOA_ADDRESS_FUNDER_NEW = '0x1c5dCdd006EA78a7E4783f9e6021C3293aaaaaaa' 
EOA_ADDRESS_FUNDER_OLD = '0xdec08cb92a506B88411da9Ba290f3694Bbbbbbbb' 
EOA_ADDRESS_FUNDED_NEW = '0x1c5dCdd006EA78a7E4783f9e6021C329cccccccc' 
EOA_ADDRESS_FUNDED_OLD = '0xdec08cb92a506B88411da9Ba290f3694Bddddddd' 

CONTRACT = '0xf11ED77fD65840b64602526DDC38311E9923c81B'


class Web3Mock:
    def __init__(self):
        self.eth = EthMock()


class EthMock:
    def __init__(self):
        self.contract = ContractMock()

    def get_transaction_count(self, address, block_number=0):
        if address.lower() == EOA_ADDRESS_SMALL_TX.lower():
            return 499
        elif address.lower() == EOA_ADDRESS_LARGE_TX.lower():
            return 501
        elif address.lower() == EOA_ADDRESS_FUNDER_NEW.lower():
            return 0
        elif address.lower() == EOA_ADDRESS_FUNDER_OLD.lower():
            return 6
        elif address.lower() == EOA_ADDRESS_FUNDED_NEW.lower():
            return 0
        elif address.lower() == EOA_ADDRESS_FUNDED_OLD.lower():
            return 6
        elif address.lower() == EOA_ADDRESS_OLD.lower():
            return 6
        return 0

    def get_code(self, address):
        if address == EOA_ADDRESS_SMALL_TX or address == EOA_ADDRESS_LARGE_TX or address == EOA_ADDRESS_OLD or address == EOA_ADDRESS_NEW:
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
