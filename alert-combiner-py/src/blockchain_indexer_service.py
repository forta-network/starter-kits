
from ratelimiter import RateLimiter
import os
import requests
import json
import rlp
import time
from io import StringIO
from web3 import Web3
import pandas as pd
import logging
from datetime import datetime, timedelta

from src.storage import get_secrets

class BlockChainIndexer:

    FIRST_BLOCK_NUMBER = 15000000
    SECRETS_JSON = None

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
    def get_zettablock_api_key():
        if BlockChainIndexer.SECRETS_JSON is None:
            BlockChainIndexer.SECRETS_JSON = get_secrets()
        
        api_key = ""

        if "ZETTABLOCK" in BlockChainIndexer.SECRETS_JSON['jsonRpc']:
            api_key = BlockChainIndexer.SECRETS_JSON['jsonRpc']['ZETTABLOCK']
        elif "ZETTABLOCK" in BlockChainIndexer.SECRETS_JSON['apiKeys']:
            api_key = BlockChainIndexer.SECRETS_JSON['apiKeys']['ZETTABLOCK']

        return api_key



    @staticmethod
    def get_api_key(chain_id):
        if BlockChainIndexer.SECRETS_JSON is None:
            BlockChainIndexer.SECRETS_JSON = get_secrets()
    
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


    # Note, this doesnt work well with contracts; caller needs to check whether address is an EOA or not
    @staticmethod
    @RateLimiter(max_calls=1, period=1)
    def get_contracts(address, chain_id, disable_etherscan=False, disable_zettablock=False) -> set:
        logging.info(f"get_contracts for {address} on {chain_id} called.")
        contracts = set()

        if not disable_etherscan:
            logging.info(f"get_contracts from etherscan for {address} on {chain_id}.")
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

        if not disable_zettablock and chain_id in [1, 137, 56]:
            logging.info(f"get_contracts from zettablock for {address} on {chain_id}.")
            try:
                endpoint = "https://api.zettablock.com/api/v1/dataset/sq_5e4eb6ce5eef480ab538ca9440ada71c/graphql"
                if chain_id == 137:
                    endpoint = "https://api.zettablock.com/api/v1/dataset/sq_0d59b127946d49c58959d6ee5b4e69d0/graphql"
                if chain_id == 56:
                    endpoint = "https://api.zettablock.com/api/v1/dataset/sq_b0a854fc15f94594a4abfb1e62ea8e74/graphql"

                query = f"""
                    {{records(
                        filter: {{
                                deployer: {{
                                    eq: "{address.lower()}"
                                }}
                            }}
                        ) {{
                            address
                            deployer
                            transaction_hash
                        }}
                    }}
                    """

                headers = {
                    "accept": "application/json",
                    "X-API-KEY": BlockChainIndexer.get_zettablock_api_key()
                }
                #headers = {'authorization': 'Basic Y2lyY2xldXNlcjE6Q2Frc1Nuc2RCbnNaYWYxMl8xMDE3'}
                data = {'query': query}

                res = requests.post(endpoint, headers=headers, data=json.dumps(data))
                if res.status_code == 200:
                    resjson = json.loads(res.text)
                    records = resjson['data']['records']
                    df = pd.DataFrame(records, columns=['address', 'deployer', 'transaction_hash'])
                    for index, row in df.iterrows():
                        contracts.add(row["address"].lower())
                else:
                    logging.warning(f"Error getting contract on zettablock for {address}, {chain_id} {res.status_code} {res.text}")

            except Exception as e:
                logging.warning(f"Error getting contract on zettablock for {address}, {chain_id} {e}")

        logging.info(f"get_contracts for {address} on {chain_id}; returning {len(contracts)}.")
        return contracts
    
    @staticmethod
    @RateLimiter(max_calls=1, period=1)
    def get_etherscan_labels(address) -> set:
        labels_url = f"https://api-metadata.etherscan.io/v1/api.ashx?module=nametag&action=getaddresstag&address={address}&tag=trusted&apikey={BlockChainIndexer.get_api_key(1)}"
        labels = set()
        success = False
        count = 0
        while not success:
            data = requests.get(labels_url)
            if data.status_code == 200:
                json_data = json.loads(data.content)
                success = True
                if "result" in json_data and len(json_data["result"]) > 0:
                    labels = json_data["result"][0]["labels"]                        
                return labels
            else:
                logging.warning(f"Error getting labels on etherscan: {data.status_code} {data.content}")
                count += 1
                if count > 10:
                    break
                time.sleep(1)
        return labels