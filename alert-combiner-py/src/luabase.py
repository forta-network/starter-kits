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

    def get_chain_name(chain_id: int) -> str:
        chain_name = ""
        if chain_id == 1:
            chain_name = "ethereum"
        elif chain_id == 137:
            chain_name = "polygon"
        else:
            raise ValueError(f"Invalid chain_id: {chain_id}")
        return chain_name

    def get_denominator(self, chain_id: int, ad_scorer: str, start_date: datetime, end_date: datetime):
        #  TODO - age out cache
        global LUABASE_CACHE

        chain_name = Luabase.get_chain_name(chain_id)

        sql = ""
        cache_key = f"{chain_name}-{ad_scorer}-{start_date.strftime('%Y-%m-%dT%H')}"
        if ad_scorer == 'contract-creation':
            sql = f"SELECT COUNT(DISTINCT hash) FROM {chain_name}.transactions WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND to_address is null"
        elif ad_scorer == 'contract-interactions':
            sql = f"SELECT COUNT(DISTINCT hash) FROM {chain_name}.transactions JOIN (SELECT address FROM {chain_name}.contracts) as contracts ON to_address == contracts.address WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' "
        elif ad_scorer == 'tx-count':
            sql = f"SELECT COUNT(DISTINCT hash) FROM {chain_name}.transactions WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}'"
        elif ad_scorer == 'transfer-in':
            sql = f"SELECT COUNT(DISTINCT hash) FROM (SELECT * FROM {chain_name}.transactions LEFT OUTER JOIN (SELECT address FROM {chain_name}.contracts) as contracts ON to_address == contracts.address WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND input== '0x' and value>0) WHERE address == ''"
        elif ad_scorer == 'transfer-out-large-amount':
            sql = f"SELECT COUNT(DISTINCT hash) FROM (SELECT * FROM {chain_name}.transactions LEFT OUTER JOIN (SELECT address FROM {chain_name}.contracts) as contracts ON from_address == contracts.address WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND input== '0x' and value>100000000000000000000) WHERE address == ''"
        elif ad_scorer == 'data-eoa-to':
            sql = f"SELECT COUNT(DISTINCT hash) FROM (SELECT * FROM {chain_name}.transactions LEFT OUTER JOIN (SELECT address FROM {chain_name}.contracts) as contracts ON to_address == contracts.address WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND input!= '0x') WHERE address == ''"
        elif ad_scorer == 'erc-approvalAll':
            sql = f"SELECT COUNT(DISTINCT hash) FROM {chain_name}.transactions WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(input AS CHAR) like '0xa22cb465%'"
        elif ad_scorer == 'erc-approvals':
            sql = f"SELECT COUNT(DISTINCT hash) FROM {chain_name}.transactions WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(input AS CHAR) like '0x095ea7b3%'"
        elif ad_scorer == 'erc-transfers':
            sql = f"SELECT COUNT(DISTINCT hash) FROM {chain_name}.transactions WHERE CAST(block_timestamp as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(block_timestamp as datetime)  <='{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(input AS CHAR) like '0xa9059cbb%'"
        else:
            raise ValueError(f"Invalid ad scorer: {ad_scorer}")

        if cache_key in LUABASE_CACHE:
            return LUABASE_CACHE[cache_key]
        else:
            value = Luabase().execute_query(sql)
            LUABASE_CACHE[cache_key] = value.iloc[0]['uniqExact(hash)']
            return value.iloc[0]['uniqExact(hash)']

    def get_alert_count(self, chain_id: int, bot_id: str, alert_id: str, start_date: datetime, end_date: datetime) -> int:
        chain_name = Luabase.get_chain_name(chain_id)

        sql = f"select COUNT() from forta.{chain_name}_alerts WHERE CAST(substring(block_timestamp,1,19) as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(substring(block_timestamp,1,19)  as datetime)  <= '{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND bot_id = '{bot_id}' AND alert_id = '{alert_id}'"
        cache_key = f"{chain_name}-{bot_id}-{alert_id}-{start_date.strftime('%Y-%m-%dT%H')}"

        if cache_key in LUABASE_CACHE:
            return LUABASE_CACHE[cache_key]
        else:
            value = Luabase().execute_query(sql)
            LUABASE_CACHE[cache_key] = value.iloc[0]['count()']
            return value.iloc[0]['count()']

