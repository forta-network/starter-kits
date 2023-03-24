from ratelimiter import RateLimiter
import os
import requests
import json
import rlp
import time
from web3 import Web3
import pandas as pd
import logging

class BlockChainIndexer:

    FIRST_BLOCK_NUMBER = 15000000
    SECRETS_JSON = json.loads(open("secrets.json").read())

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

        df_etherscan = pd.DataFrame(columns=['nonce', 'to', 'isError'])

        transaction_for_address = f"{BlockChainIndexer.get_etherscan_url(chain_id)}/api?module=account&action=txlist&address={address}&startblock={BlockChainIndexer.FIRST_BLOCK_NUMBER}&endblock=99999999&page=1&offset=10000&sort=asc&apikey={BlockChainIndexer.get_api_key(chain_id)}"
        
        success = False
        count = 0
        while not success:
            try:
                data = requests.get(transaction_for_address)
                json_data = json.loads(data.content)
                count += 1
                if count > 10:
                    break
                success = True
                df_etherscan = df_etherscan.append(pd.DataFrame(data=json_data["result"]))
            except json.JSONDecodeError as e:
                logging.warn(f"Error getting contract for {address}, {chain_id} {e} {data.content}")
                time.sleep(1)
        
        for index, row in df_etherscan.iterrows():
            if row["isError"] == "0":
                if row["to"] == "":
                    contracts.add(BlockChainIndexer.calc_contract_address(address, int(row["nonce"])).lower())

        return contracts
