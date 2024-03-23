
from ratelimiter import RateLimiter
import os
import requests
import json
import rlp
import traceback
import time
from io import StringIO
from web3 import Web3
import pandas as pd
import logging
import random
from functools import lru_cache
from datetime import datetime, timedelta

from src.storage import get_secrets
from src.utils import Utils
from src.constants import CONTRACTS_TX_COUNT_FILTER_THRESHOLD

class BlockChainIndexer:

    SECRETS_JSON = None

    @staticmethod
    def get_first_block_number(chain_id):
        if chain_id == 1:
            return 16000000
        elif chain_id == 137:
            return  37000000
        elif chain_id == 56:
            return  23000000
        elif chain_id == 42161:
            return 50000000
        elif chain_id == 10:
            return 35000000
        elif chain_id == 250:
            return 50000000
        elif chain_id == 43114:
            return 33000000

        raise Exception("Chain ID not supported")

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
            start_block = BlockChainIndexer.get_first_block_number(chain_id)
            # Snowtrace now allows up to a 1M blockrange
            end_block = 99999999 if chain_id != 43114 else start_block + 999999
            transaction_for_address = f"{BlockChainIndexer.get_etherscan_url(chain_id)}/api?module=account&action=txlist&address={address}&startblock={start_block}&endblock={end_block}&page=1&offset=10000&sort=asc&apikey={BlockChainIndexer.get_api_key(chain_id)}"

            success = False
            count = 0
            while not success:
                data = requests.get(transaction_for_address)
                if data.status_code == 200:
                    success = True
                    json_data = json.loads(data.content)
                    if "result" in json_data and json_data["result"] is not None and len(json_data["result"])>0 and isinstance(json_data["result"], list):
                        df_etherscan_temp = pd.DataFrame(data=json_data["result"])
                        df_etherscan = pd.concat([df_etherscan, df_etherscan_temp], axis=0)
                else:
                    logging.warning(f"Error getting contract on etherscan for {address}, {chain_id} {data.status_code} {data.content}")
                    count += 1
                    if count > 10:
                        Utils.ERROR_CACHE.add(Utils.alert_error(f'request etherscan {data.status_code}', "blockchain_indexer_service.get_contracts", ""))
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
                    Utils.ERROR_CACHE.add(Utils.alert_error(f'request zettablock {res.status_code}', "blockchain_indexer_service.get_contracts", ""))
                    logging.warning(f"Error getting contract on zettablock for {address}, {chain_id} {res.status_code} {res.text}")

            except Exception as e:
                logging.warning(f"Error getting contract on zettablock for {address}, {chain_id} {e}")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "blockchain_indexer_service.get_contracts", traceback.format_exc()))


        logging.info(f"get_contracts for {address} on {chain_id}; returning {len(contracts)}.")
        return contracts
    
    @staticmethod
    @RateLimiter(max_calls=1, period=1)
    def has_deployed_high_tx_count_contract(cluster: str, chain_id) -> bool:
        for address in cluster.split(','):
            contracts = BlockChainIndexer.get_contracts(address, chain_id)
            logging.info(f"has_deployed_high_tx_count_contract for address {address} on {chain_id} called.")

            for contract in contracts:
                start_block = BlockChainIndexer.get_first_block_number(chain_id)
                # Snowtrace now allows up to a 1M blockrange
                end_block = 99999999 if chain_id != 43114 else start_block + 999999

                transactions_for_contract = f"{BlockChainIndexer.get_etherscan_url(chain_id)}/api?module=account&action=txlist&address={contract}&startblock={start_block}&endblock={end_block}&page=1&offset=10000&sort=asc&apikey={BlockChainIndexer.get_api_key(chain_id)}"

                success = False
                count = 0
                while not success:
                    data = requests.get(transactions_for_contract)
                    if data.status_code == 200:
                        json_data = json.loads(data.content)
                        success = True
                        if len(json_data["result"]) > CONTRACTS_TX_COUNT_FILTER_THRESHOLD:
                            return True                   
                    else:
                        logging.warning(f"Error getting contract on etherscan for {contract}, {chain_id} {data.status_code} {data.content}")
                        count += 1
                        if count > 10:
                            Utils.ERROR_CACHE.add(Utils.alert_error(f'request etherscan {data.status_code}', "blockchain_indexer_service.get_contracts", ""))
                            break
                        time.sleep(1)
        return False
    
    @staticmethod
    @lru_cache(maxsize=512)
    @RateLimiter(max_calls=1, period=1)
    def get_etherscan_labels(addresses) -> dict: #address -> {'labels': ['XXXXX'], 'nametag': 'YYYYYY'}
        address_labels = dict()
        wait_time = 1 # seconds
        try:
            addresses_str = ','.join(addresses)
            labels_url = f"https://api-metadata.etherscan.io/v1/api.ashx?module=nametag&action=getaddresstag&address={addresses_str}&tag=trusted&apikey={BlockChainIndexer.get_api_key(1)}"         
            
            success = False
            count = 0
            while not success:
                data = requests.get(labels_url)
                json_data = json.loads(data.content)
                if data.status_code == 200 and json_data['status'] == '1':
                    success = True
                    if isinstance(json_data["result"], list):
                        for result in json_data["result"]:
                            if len(result["labels"]):
                                address_labels[result["address"]] = {
                                    "labels": result["labels"],
                                    "nametag": result.get("nametag", "")  # Include nametag if it exists, otherwise an empty string
                                }
                    else:
                        logging.warning(f"Error getting labels on etherscan: {data.status_code} {data.content}")
                    for address, data in address_labels.items():
                        labels = data["labels"]
                        nametag = data["nametag"]
                        logging.info(f"Labels for address {address}: {', '.join(labels)}, Nametag: {nametag}")
                    return address_labels
                else:
                    if json_data['message'] == 'No matching records found':
                        logging.info(f"No matching Etherscan labels found for {addresses_str}")
                        return address_labels
                    logging.warning(f"Error getting labels on etherscan: {data.status_code} {data.content}")
                    count += 1
                    if count > 10:
                        Utils.ERROR_CACHE.add(Utils.alert_error(f'request etherscan {data.status_code}', "blockchain_indexer_service.get_etherscan_labels", ""))
                        break
                    # Exponential backoff with jitter
                    time_to_sleep = wait_time + random.uniform(-0.3 * wait_time, 0.3 * wait_time)
                    time.sleep(time_to_sleep)
                    wait_time = min(wait_time * 2, 7)  # Ensure wait time does not exceed 7 seconds
        except Exception as e:
            logging.warning(f"Error getting labels on etherscan: {e}")
            Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "blockchain_indexer_service.get_etherscan_labels", traceback.format_exc()))
            
        return address_labels