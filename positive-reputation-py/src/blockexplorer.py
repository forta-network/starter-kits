import json
import logging
import datetime
import requests
from web3 import Web3
import rlp
import pandas as pd

from src.storage import get_secrets
from src.constants import CONTRACTS_TX_COUNT_FILTER_THRESHOLD

class BlockExplorer:
    api_key = ""
    zettablock_key = ""

    host = ""
    SECRETS_JSON = None

    def __init__(self, chain_id):
        if BlockExplorer.SECRETS_JSON is None:
            BlockExplorer.SECRETS_JSON = get_secrets()

        if "ZETTABLOCK" in BlockExplorer.SECRETS_JSON['jsonRpc']:
            self.zettablock_key = BlockExplorer.SECRETS_JSON['jsonRpc']['ZETTABLOCK']
        elif "ZETTABLOCK" in BlockExplorer.SECRETS_JSON['apiKeys']:
            self.zettablock_key = BlockExplorer.SECRETS_JSON['apiKeys']['ZETTABLOCK']  

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
        url = self.host + f"/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey={self.api_key}"
        response = requests.get(url)
        if (response.status_code == 200):
            data = json.loads(response.text)
            df_txs = pd.DataFrame(data["result"])
            if len(df_txs) > 0:
                return datetime.datetime.fromtimestamp(int(df_txs["timeStamp"].min()))
        else:
            logging.warn("Unable obtain tx for account. Etherscan returned status code " + str(response.status_code))

    @staticmethod
    def calc_contract_address(address, nonce) -> str:
        """
        this function calculates the contract address from sender/nonce
        :return: contract address: str
        """

        address_bytes = bytes.fromhex(address[2:].lower())
        return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])

    def get_contracts(self, address, chain_id, disable_etherscan=False, disable_zettablock=False) -> set:
        logging.info(f"get_contracts for {address} on {chain_id} called.")
        contracts = set()

        if not disable_etherscan:
            logging.info(f"get_contracts from etherscan for {address} on {chain_id}.")
            df_etherscan = pd.DataFrame(columns=['nonce', 'to', 'isError'])
            transaction_for_address = self.host + f"/api?module=account&action=txlist&address={address}&startblock=0&endblock=999999999&page=1&offset=10000&sort=asc&apikey={self.api_key}"
            
            success = False
            count = 0
            while not success:
                data = requests.get(transaction_for_address)
                if data.status_code == 200:
                    json_data = json.loads(data.content)
                    success = True
                    df_etherscan_temp = pd.DataFrame(data=json_data.get("result", []) if isinstance(json_data.get("result"), list) else [])
                    df_etherscan = pd.concat([df_etherscan, df_etherscan_temp], axis=0)
                else:
                    logging.warning(f"Error getting contract on etherscan for {address}, {chain_id} {data.status_code} {data.content}")
                    count += 1
                    if count > 10:                    
                        break
        
            for index, row in df_etherscan.iterrows():
                if row["isError"] == "0":
                    if row["to"] == "":
                        contracts.add(self.calc_contract_address(address, int(row["nonce"])).lower())

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
                    "X-API-KEY": self.zettablock_key
                }
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

    def has_deployed_high_tx_count_contract(self, address, chain_id) -> bool:
        contracts = self.get_contracts(address, chain_id)
        logging.info(f"has_deployed_high_tx_count_contract for address {address} on {chain_id} called.")

        for contract in contracts:
            transactions_for_contract = self.host + f"/api?module=account&action=txlist&address={contract}&startblock=0&endblock=999999999&page=1&offset=10000&sort=asc&apikey={self.api_key}"

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
                        break
        return False
