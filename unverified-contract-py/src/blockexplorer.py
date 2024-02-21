import json
import logging
import aiohttp
import requests
from storage import get_secrets

class BlockExplorer:
    api_key = ""
    host = ""
    chain_id = None
    SECRETS_JSON = None

    def __init__(self, chain_id):
        self.chain_id = chain_id

        if chain_id == 1:
            self.host = "https://api.etherscan.io"
        elif chain_id == 137:
            self.host = "https://api.polygonscan.com"
        elif chain_id == 56:
            self.host = "https://api.bscscan.com"
        elif chain_id == 42161:
            self.host = "https://api.arbiscan.io"
        elif chain_id == 10:
            self.host = "https://api-optimistic.etherscan.io"
        elif chain_id == 250:
            self.host = "https://api.ftmscan.com"
        elif chain_id == 43114:
            self.host = "https://api.snowtrace.io"

    async def set_api_key(self):
        if BlockExplorer.SECRETS_JSON is None:
            BlockExplorer.SECRETS_JSON = await get_secrets()

        if self.chain_id == 1:
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['ETHERSCAN_TOKEN']
        elif self.chain_id == 137:
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['POLYGONSCAN_TOKEN']
        elif self.chain_id == 56:
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['BSCSCAN_TOKEN']
        elif self.chain_id == 42161:
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['ARBISCAN_TOKEN']
        elif self.chain_id == 10:
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['OPTIMISTICSCAN_TOKEN']
        elif self.chain_id == 250:
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['FTMSCAN_TOKEN']
        elif self.chain_id == 43114:
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['SNOWTRACE_TOKEN']

    async def is_verified(self, address):
        url = self.host + "/api?module=contract&action=getabi&address=" + address + "&apikey=" + self.api_key
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as res:
                if res.status == 200:
                    try:
                        # Attempt to parse the response as JSON regardless of the Content-Type
                        data = await res.json(content_type=None)
                        if data['status'] == '1':
                            return True
                    except json.JSONDecodeError:
                        raise Exception("Failed to decode JSON response")
                else:
                    logging.warn("Unable to retrieve ABI. Etherscan returned status code " + str(res.status))
                    pass