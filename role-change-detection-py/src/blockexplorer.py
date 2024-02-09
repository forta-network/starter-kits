import json
import logging
import requests
from functools import lru_cache

from src.storage import get_secrets


class BlockExplorer:
    api_key = ""
    host = ""
    SECRETS_JSON = None

    def __init__(self, chain_id):
        if BlockExplorer.SECRETS_JSON is None:
            BlockExplorer.SECRETS_JSON = get_secrets()

        if chain_id == 1:
            self.host = "https://api.etherscan.io"
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['ETHERSCAN_TOKEN']
        elif chain_id == 137:
            self.host = "https://api.polygonscan.com"
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['POLYGONSCAN_TOKEN']
        elif chain_id == 56:
            self.host = "https://api.bscscan.com"
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['BSCSCAN_TOKEN']
        elif chain_id == 42161:
            self.host = "https://api.arbiscan.io"
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['ARBISCAN_TOKEN']
        elif chain_id == 10:
            self.host = "https://api-optimistic.etherscan.io"
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['OPTIMISTICSCAN_TOKEN']
        elif chain_id == 250:
            self.host = "https://api.ftmscan.com"
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['FTMSCAN_TOKEN']
        elif chain_id == 43114:
            self.host = "https://api.snowtrace.io"
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['SNOWTRACE_TOKEN']


    @lru_cache(maxsize=128000)
    def get_abi(self, address):
        url = self.host + "/api?module=contract&action=getabi&address=" + address + "&apikey=" + self.api_key
        response = requests.get(url)
        if (response.status_code == 200):
            data = response.json()
            if data['status'] == '1':
                abi = data['result']
                return abi
        else:
            logging.warn("Unable to retrieve ABI. Etherscan returned status code " + str(response.status_code))
            pass
