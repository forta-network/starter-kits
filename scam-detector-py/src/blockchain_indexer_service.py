from ratelimiter import RateLimiter
import os
import requests
import json
from dotenv import load_dotenv
import pandas as pd

class BlockChainIndexer:

    FIRST_BLOCK_NUMBER = 15000000

    @staticmethod
    def get_etherscan_url(chain_id):
        if os.environ.get('ETHERSCAN_TOKEN') is None:
            load_dotenv()
        return ""

    @staticmethod
    def get_etherscan_api_key(chain_id):
        if os.environ.get('ETHERSCAN_TOKEN') is None:
            load_dotenv()
        return ""

    @staticmethod
    @RateLimiter(max_calls=1, period=1)
    def get_contracts(address, chain_id):
        df_etherscan = pd.DataFrame(columns=['blockNumber', 'timeStamp', 'hash', 'nonce', 'blockHash',
                                             'transactionIndex', 'from', 'to', 'value', 'gas', 'gasPrice', 'isError',
                                             'txreceipt_status', 'input', 'contractAddress', 'cumulativeGasUsed',
                                             'gasUsed', 'confirmations', 'type', 'traceId', 'errCode'])

        for address in addresses:
            etherscan_transaction_for_address = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock={FIRST_BLOCK_NUMBER}&endblock=99999999&page=1&offset=10000&sort=asc&apikey={os.environ.get('ETHERSCAN_TOKEN')}"
            #etherscan_transaction_for_address = f"https://api-goerli.etherscan.io/api?module=account&action=txlist&address={address}&startblock={firstBlockNumber}&endblock=99999999&page=1&offset=10000&sort=asc&apikey={os.environ.get('ETHERSCAN_TOKEN')}"
            
            data = requests.get(etherscan_transaction_for_address)
            success2 = False
            count = 0
            while not success2:
                try:
                    data = requests.get(etherscan_transaction_for_address)
                    json_data = json.loads(data.content)
                    count += 1
                    if count > 10:
                        break
                    success2 = True
                    df_etherscan = df_etherscan.append(pd.DataFrame(data=json_data["result"]))
                except JSONDecodeError as e:
                    print(f"Error {e} {data.content}")
                    time.sleep(1)
            if count>10:
                continue