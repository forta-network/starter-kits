import json
import logging

import requests


class Etherscan:
    api_key = ""

    def __init__(self, api_key):
        self.api_key = api_key

    def is_verified(self, address):
        url = "https://api.etherscan.io/api?module=contract&action=getabi&address=" + address + "&apikey=" + self.api_key
        response = requests.get(url)
        if (response.status_code == 200):
            data = json.loads(response.text)
            if data['status'] == '1':
                return True
        else:
            logging.warn("Unable to check if contract is verified. Etherscan returned status code " + str(response.status_code))

        return False
