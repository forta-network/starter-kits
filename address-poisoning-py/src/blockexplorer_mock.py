class BlockExplorerMock():

    def __init__(self, chain_id):
        if chain_id == 1:
            self.key = ""
            self.endpoint = ""


    def make_token_history_query(self, address_info):
        if address_info[0] == "victim":
            return [0, 10000, 5000, 0, 823400]
        else:
            return [0, 0, 0, 0, 0]


    def is_verified(self, address):
        return False