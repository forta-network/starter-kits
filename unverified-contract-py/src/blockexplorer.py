import json
import logging

import requests

from src.api_keys import BSC_API_KEY, ETHERSCAN_API_KEY, POLYGON_API_KEY, ARBITRUM_API_KEY, OPTIMISM_API_KEY, FANTOM_API_KEY, AVALANCHE_API_KEY


class BlockExplorer:
    api_key = ""
    host = ""

    def __init__(self, chain_id):
        if chain_id == 1:
            self.host = "https://api.etherscan.io"
            self.api_key = ETHERSCAN_API_KEY
        elif chain_id == 137:
            self.host = "https://api.polygonscan.com"
            self.api_key = POLYGON_API_KEY
        elif chain_id == 56:
            self.host = "https://api.bscscan.com"
            self.api_key = BSC_API_KEY
        elif chain_id == 42161:
            self.host = "https://api.arbiscan.io"
            self.api_key = ARBITRUM_API_KEY
        elif chain_id == 10:
            self.host = "https://api-optimistic.etherscan.io"
            self.api_key = OPTIMISM_API_KEY
        elif chain_id == 250:
            self.host = "https://api.ftmscan.com"
            self.api_key = FANTOM_API_KEY
        elif chain_id == 43114:
            self.host = "https://api.snowtrace.io"
            self.api_key = AVALANCHE_API_KEY
    

    def is_verified(self, address):
        url = self.host + "/api?module=contract&action=getabi&address=" + address + "&apikey=" + self.api_key
        response = requests.get(url)
        if (response.status_code == 200):
            data = json.loads(response.text)
            if data['status'] == '1':
                return True
        else:
            logging.warn("Unable to check if contract is verified. Etherscan returned status code " + str(response.status_code))

        return False
