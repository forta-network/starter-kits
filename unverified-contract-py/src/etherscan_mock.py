VERIFIED_CONTRACT = '0xD56A0d6fe38cD6153C7B26ECE11b405BCADfF253'
UNVERIFIED_CONTRACT = '0x728ad672409DA288cA5B9AA85D1A55b803bA97D7'


class EtherscanMock:

    def is_verified(self, address):
        if address == VERIFIED_CONTRACT:
            return True
        elif address == UNVERIFIED_CONTRACT:
            return False
        else:
            return False
