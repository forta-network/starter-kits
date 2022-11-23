import datetime
import requests
import pandas as pd
import os
from dotenv import load_dotenv
load_dotenv()

LUABASE_CACHE = {}


class Luabase:
    def execute_query(self, sql: str) -> pd.DataFrame:
        url = "https://q.luabase.com/run"
        payload = {"block": 
                   {"details": {
                    "sql": sql,
                    }
                    },
                   "api_key": os.environ.get('LUABASE_API_KEY')
                   }

        headers = {"content-type": "application/json"}
        response = requests.request("POST", url, json=payload, headers=headers)
        data = response.json()
        print(data)
        return pd.DataFrame(data["data"])

    def get_denominator(self, ad_scorer: str, start_date: datetime, end_date: datetime):
        #  TODO - age out cache
        global LUABASE_CACHE

        sql = ""
        if ad_scorer == 'contract-creation':
            sql = f"SELECT COUNT(DISTINCT hash) FROM ethereum.transactions WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}' AND to_address is null"
        elif ad_scorer == 'contract-interactions':
            sql = f"SELECT COUNT(DISTINCT hash) FROM ethereum.transactions JOIN (SELECT address FROM ethereum.contracts) as contracts ON to_address == contracts.address WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}' "
        elif ad_scorer == 'tx-count':
            sql = f"SELECT COUNT(DISTINCT hash) FROM ethereum.transactions WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}'"
        elif ad_scorer == 'transfer-in':
            sql = f"SELECT COUNT(DISTINCT hash) FROM (SELECT * FROM ethereum.transactions LEFT OUTER JOIN (SELECT address FROM ethereum.contracts) as contracts ON to_address == contracts.address WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}' AND input== '0x' and value>0) WHERE address == ''"
        elif ad_scorer == 'transfer-out-large-amount':
            sql = f"SELECT COUNT(DISTINCT hash) FROM (SELECT * FROM ethereum.transactions LEFT OUTER JOIN (SELECT address FROM ethereum.contracts) as contracts ON from_address == contracts.address WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}' AND input== '0x' and value>100000000000000000000) WHERE address == ''"
        elif ad_scorer == 'data-eoa-to':
            sql = f"SELECT COUNT(DISTINCT hash) FROM (SELECT * FROM ethereum.transactions LEFT OUTER JOIN (SELECT address FROM ethereum.contracts) as contracts ON to_address == contracts.address WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}' AND input!= '0x') WHERE address == ''"
        elif ad_scorer == 'erc-approvalAll':
            sql = f"SELECT COUNT(DISTINCT hash) FROM ethereum.transactions WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}' AND CAST(input AS CHAR) like '0xa22cb465%'"
        elif ad_scorer == 'erc-approvals':
            sql = f"SELECT COUNT(DISTINCT hash) FROM ethereum.transactions WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}' AND CAST(input AS CHAR) like '0x095ea7b3%'"
        elif ad_scorer == 'erc-transfers':
            sql = f"SELECT COUNT(DISTINCT hash) FROM ethereum.transactions WHERE CAST(block_timestamp as date)  >= '{start_date.strftime('%Y-%m-%d')}' AND CAST(block_timestamp as date)  <='{end_date.strftime('%Y-%m-%d')}' AND CAST(input AS CHAR) like '0xa9059cbb%'"
        else:
            raise ValueError(f"Invalid ad scorer: {ad_scorer}")

        if sql in LUABASE_CACHE:
            return LUABASE_CACHE[sql]
        else:
            value = Luabase().execute_query(sql)
            LUABASE_CACHE[sql] = value.iloc[0]['uniqExact(hash)']
            return value.iloc[0]['uniqExact(hash)']