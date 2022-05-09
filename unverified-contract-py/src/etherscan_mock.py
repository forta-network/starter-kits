VERIFIED_CONTRACT = '0x728ad672409DA288cA5B9AA85D1A55b803bA97D7'
UNVERIFIED_CONTRACT = '0x2320A28f52334d62622cc2EaFa15DE55F9987eD9'


class EtherscanMock:

    def is_verified(self, address):
        if address == VERIFIED_CONTRACT:
            return True
        elif address == UNVERIFIED_CONTRACT:
            return False
        else:
            return False
