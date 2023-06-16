
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
    def sql_to_csv(querystr: str) -> str:
        timeout_sec = 5 * 60  # 5 minutes

        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            # credentials
            "X-API-KEY": BlockChainIndexer.get_zettablock_api_key()
        }

        data_lake_query_endpoint = "https://api.zettablock.com/api/v1/databases/AwsDataCatalog/queries"

        # specify how long you want to cache the result
        query = {"query":querystr, "resultCacheExpireMillis": 86400000}

        # Create a query with SQL statement, and get query id
        res = requests.post(data_lake_query_endpoint, headers=headers, data=json.dumps(query))

        if res.status_code == 200:
            query_id = res.json()['id']

            data_lake_submission_endpoints = f'https://api.zettablock.com/api/v1/queries/{query_id}/trigger'
            res = requests.post(data_lake_submission_endpoints, headers=headers, data='{}')

            if res.status_code == 200:
                # Check status using queryrun id
                queryrun_id = res.json()['queryrunId']

                def get_response(queryrun_id):
                    import time
                    i = 1
                    queryrun_status_endpoint = f'https://api.zettablock.com/api/v1/queryruns/{queryrun_id}/status'
                    while True:
                        res = requests.get(queryrun_status_endpoint, headers=headers)
                        state = json.loads(res.text)['state']
                        logging.info(f"Zettablock state {i}: {state}")
                        if state == 'SUCCEEDED' or state == 'FAILED':
                            return state
                        time.sleep(1)
                        if i > timeout_sec:
                            return state
                        i += 1
            
                if get_response(queryrun_id) == 'SUCCEEDED':
                    # Fetch result from queryrun id
                    params = {'includeColumnName': 'true'}
                    queryrun_result_endpoint = f'https://api.zettablock.com/api/v1/stream/queryruns/{queryrun_id}/result'
                    # if the result is huge, consider using stream and write to a file
                    res = requests.get(queryrun_result_endpoint, headers=headers, params=params)
                    return res.text
                else:
                    raise ConnectionError(f"Execution of zettablock query {querystr} failed.")
            else:
                raise ConnectionError(f"Execution of zettablock query {querystr} failed with {res.status_code}")
        else:
            raise ConnectionError(f"Execution of zettablock query {querystr} failed with {res.status_code}")

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
                table_name = "ethereum_mainnet.contract_creations"
                if chain_id == 137:
                    table_name = "polygon_mainnet.contract_creations"
                if chain_id == 56:
                    table_name = "bsc_mainnet.contract_creations"

                # address, deployer, transaction_hash
                query_str = f"""SELECT address, creator_address AS deployer, transaction_hash FROM ethereum_mainnet.contract_creations WHERE LOWER(creator_address) = '{address.lower()}' LIMIT 500"""

                csv_str = BlockChainIndexer.sql_to_csv(query_str)
                data = StringIO(csv_str)

                # Read the data into a DataFrame
                df = pd.read_csv(data)
                for index, row in df.iterrows():
                    contracts.add(row["address"].lower())

            except Exception as e:
                logging.warning(f"Error getting contract on zettablock for {address}, {chain_id} {e}")

        logging.info(f"get_contracts for {address} on {chain_id}; returning {len(contracts)}.")
        return contracts