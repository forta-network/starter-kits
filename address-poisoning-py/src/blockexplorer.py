from src.storage import get_secrets
from functools import lru_cache
import requests
import logging
import json

class BlockExplorer():

    def __init__(self, chain_id):
        self.api_keys = get_secrets()

        if chain_id == 1:
            self.host = "https://api.etherscan.io/api"
            self.api_key = self.api_keys['apiKeys']['ETHERSCAN_TOKEN']
        elif chain_id == 137:
            self.host = "https://api.polygonscan.com/api"
            self.api_key = self.api_keys['apiKeys']['POLYGONSCAN_TOKEN']
        elif chain_id == 56:
            self.host = "https://api.bscscan.com/api"
            self.api_key = self.api_keys['apiKeys']['BSCSCAN_TOKEN']
        elif chain_id == 42161:
            self.host = "https://api.arbiscan.io/api"
            self.api_key = self.api_keys['apiKeys']['ARBISCAN_TOKEN']
        elif chain_id == 10:
            self.host = "https://api-optimistic.etherscan.io/api"
            self.api_key = self.api_keys['apiKeys']['OPTIMISTICSCAN_TOKEN']
        elif chain_id == 250:
            self.host = "https://api.ftmscan.com/api"
            self.api_key = self.api_keys['apiKeys']['FTMSCAN_TOKEN']
        elif chain_id == 43114:
            self.host = "https://api.snowtrace.io/api"
            self.api_key = self.api_keys['apiKeys']['SNOWTRACE_TOKEN']


    @lru_cache(maxsize=100)
    def make_token_history_query(self, address_info):
        params = {
            "module": "account",
            "action": "tokentx",
            "contractaddress": address_info[1],
            "address": address_info[0],
            "apikey": self.api_key
        }

        response = requests.get(self.host, params=params)
        values = [transfer['value'] for transfer in response.json()['result'] if transfer['from'] == str.lower(address_info[0])]
        
        return values[-5:]

    def is_verified(self, address):
        url = self.host + "?module=contract&action=getabi&address=" + address + "&apikey=" + self.api_key
        response = requests.get(url)
        if (response.status_code == 200):
            data = json.loads(response.text)
            if data['status'] == '1':
                logging.info("Contract is verified...exiting")
                return True
        else:
            logging.warn("Unable to check if contract is verified. Etherscan returned status code " + str(response.status_code))
        logging.info("Contract is not verified")
        return False