
from ratelimiter import RateLimiter
import os
import requests
import json
import rlp
import time
from web3 import Web3
import pandas as pd
import logging

from src.storage import get_secrets

class BlockChainIndexer:

    FIRST_BLOCK_NUMBER = 15000000
    SECRETS_JSON = get_secrets()

    @staticmethod
    def get_etherscan_url(chain_id):
        if chain_id == 1:
            return "https://api.etherscan.io"
        elif chain_id == 137:
            return  "https://api.polygonscan.com"
        elif chain_id == 56:
            return  "https://api.bscscan.com"
        elif chain_id == 42161:
            return "https://api.arbiscan.io"
        elif chain_id == 10:
            return "https://api-optimistic.etherscan.io"
        elif chain_id == 250:
            return "https://api.ftmscan.com"
        elif chain_id == 43114:
            return "https://api.snowtrace.io"

        raise Exception("Chain ID not supported")

    @staticmethod
    def get_allium_query(chain_id):
        if chain_id == 1:
            return "JhpUSRVEYONMoFqXrbKY"
        elif chain_id == 137:
            return  "RYr8M3SYvoamKaMSrJn3"
        elif chain_id == 42161:
            return "gfEcYla8Tk5qPAIpextm"
        elif chain_id == 10:
            return "gfEcYla8Tk5qPAIpextm"
        elif chain_id == 250:
            return "https://api.ftmscan.com"

        raise Exception("Chain ID not supported")

    @staticmethod
    def get_allium_api_key():
        if "ALLIUM" in BlockChainIndexer.SECRETS_JSON['apiKeys']:
            return BlockChainIndexer.SECRETS_JSON['apiKeys']['ALLIUM']
        else:
            return ""

    @staticmethod
    def get_api_key(chain_id):
        if chain_id == 1:
            return BlockChainIndexer.SECRETS_JSON['apiKeys']['ETHERSCAN_TOKEN']
        elif chain_id == 137:
            return BlockChainIndexer.SECRETS_JSON['apiKeys']['POLYGONSCAN_TOKEN']
        elif chain_id == 56:
            return BlockChainIndexer.SECRETS_JSON['apiKeys']['BSCSCAN_TOKEN']
        elif chain_id == 42161:
            return BlockChainIndexer.SECRETS_JSON['apiKeys']['ARBISCAN_TOKEN']
        elif chain_id == 10:
            return BlockChainIndexer.SECRETS_JSON['apiKeys']['OPTIMISTICSCAN_TOKEN']
        elif chain_id == 250:
            return BlockChainIndexer.SECRETS_JSON['apiKeys']['FTMSCAN_TOKEN']
        elif chain_id == 43114:
            return BlockChainIndexer.SECRETS_JSON['apiKeys']['SNOWTRACE_TOKEN']
        
        raise Exception("Chain ID not supported")

    @staticmethod
    def calc_contract_address(address, nonce) -> str:
        """
        this function calculates the contract address from sender/nonce
        :return: contract address: str
        """

        address_bytes = bytes.fromhex(address[2:].lower())
        return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


    @staticmethod
    @RateLimiter(max_calls=1, period=1)
    def get_contracts(address, chain_id) -> set:
        contracts = set()

        #etherscan for all chains except bsc and fantom
        df_etherscan = pd.DataFrame(columns=['nonce', 'to', 'isError'])
        transaction_for_address = f"{BlockChainIndexer.get_etherscan_url(chain_id)}/api?module=account&action=txlist&address={address}&startblock={BlockChainIndexer.FIRST_BLOCK_NUMBER}&endblock=99999999&page=1&offset=10000&sort=asc&apikey={BlockChainIndexer.get_api_key(chain_id)}"
        
        success = False
        count = 0
        while not success:
            data = requests.get(transaction_for_address)
            if data.status_code == 200:
                json_data = json.loads(data.content)
                success = True
                df_etherscan_temp = pd.DataFrame(data=json_data["result"])
                df_etherscan = pd.concat([df_etherscan, df_etherscan_temp], axis=0)
            else:
                logging.warning(f"Error getting contract on etherscan for {address}, {chain_id} {data.status_code} {data.content}")
                count += 1
                if count > 10:
                    break
                time.sleep(1)
    
        for index, row in df_etherscan.iterrows():
            if row["isError"] == "0":
                if row["to"] == "":
                    contracts.add(BlockChainIndexer.calc_contract_address(address, int(row["nonce"])).lower())

        if chain_id != 56 and chain_id != 250:
            response = requests.post(f"https://api.allium.so/api/v1/explorer/queries/{BlockChainIndexer.get_allium_query(chain_id)}/run",
                json={"address_lower":address},
                headers={"X-API-Key": BlockChainIndexer.get_allium_api_key()},
            )
            if response.status_code == 200:
                json_data = json.loads(response.content)
                df_allium_temp = pd.DataFrame(data=json_data["data"])
                for index, row in df_allium_temp.iterrows():
                    contracts.add(row["address"].lower())
            else:
                logging.warning(f"Error getting contract on allium for {address}, {chain_id} {response.status_code} {response.content}")

        return contracts