import json
import logging
import requests
import aiohttp
from async_lru import alru_cache

from storage import get_secrets


class BlockExplorer:
    api_key = ""
    host = ""
    chain_id = None
    SECRETS_JSON = None

    def __init__(self, chain_id):
        self.chain_id = chain_id

        if self.chain_id == 1:
            self.host = "https://api.etherscan.io"
        elif self.chain_id == 137:
            self.host = "https://api.polygonscan.com"
        elif self.chain_id == 56:
            self.host = "https://api.bscscan.com"
        elif self.chain_id == 42161:
            self.host = "https://api.arbiscan.io"
        elif self.chain_id == 10:
            self.host = "https://api-optimistic.etherscan.io"
        elif self.chain_id == 250:
            self.host = "https://api.ftmscan.com"
        elif self.chain_id == 43114:
            self.host = "https://api.snowtrace.io"
        elif self.chain_id == 8453:
            self.host = "https://api.basescan.org"

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
        elif self.chain_id == 8453:
            self.api_key = BlockExplorer.SECRETS_JSON['apiKeys']['BASESCAN_TOKEN']


    @alru_cache(maxsize=128000)
    async def get_abi(self, address):
        url = self.host + "/api?module=contract&action=getabi&address=" + address + "&apikey=" + self.api_key
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as res:
                if res.status == 200:
                    try:
                        # Attempt to parse the response as JSON regardless of the Content-Type
                        data = await res.json(content_type=None)
                        if data['status'] == '1':
                            abi = data['result']
                            return abi
                    except json.JSONDecodeError:
                        raise Exception("Failed to decode JSON response")
                else:
                    logging.warn("Unable to retrieve ABI. Etherscan returned status code " + str(response.status_code))
                    pass