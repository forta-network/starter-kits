import json
import logging
import datetime
import requests
import pandas as pd

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

    def get_first_tx(self, address: str) -> datetime:
        url = self.host + \
            f"/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey={self.api_key}"
        response = requests.get(url)
        if (response.status_code == 200):
            data = json.loads(response.text)

            if len(data["result"]) == 0:
                timestamp = int(datetime.datetime.now().timestamp())
                return datetime.datetime.fromtimestamp(timestamp)

            df_txs = pd.DataFrame(data["result"])

            if len(df_txs) > 0:
                return datetime.datetime.fromtimestamp(int(df_txs["timeStamp"].min()))
        else:
            logging.warn(
                "Unable obtain tx for account. Etherscan returned status code " + str(response.status_code))
