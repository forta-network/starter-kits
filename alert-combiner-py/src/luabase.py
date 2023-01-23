# Copyright 2022 The Forta Foundation

import datetime
import requests
import pandas as pd
import os
import logging

from src.constants import BASE_BOTS, LUABASE_QUERY_FREQUENCY_IN_HOURS, LOCAL_NODE
from src.L2Cache import L2Cache

from dotenv import load_dotenv
load_dotenv()


LUABASE_CACHE_L1 = {}
MAX_LUA_CACHE_SIZE = 1000
MUTEX_LUABASE = False


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
        logging.debug(f"Executing query: {sql}")
        response = requests.request("POST", url, json=payload, headers=headers, timeout=600)  # 10min timeout
        logging.debug(f"Executed query: {sql}. Response code: {response.status_code}")
        data = response.json()
        return pd.DataFrame(data["data"])

    def get_chain_name(chain_id: int) -> str:
        chain_name = ""
        if chain_id == 1:
            chain_name = "ethereum"
        elif chain_id == 137:
            chain_name = "polygon"
        elif chain_id == 43114:
            chain_name = "avalanche"
        elif chain_id == 250:
            chain_name = "fantom"
        else:
            raise ValueError(f"Invalid chain_id: {chain_id}")
        return chain_name

    def get_denominator(self, chain_id: int, ad_scorer: str, start_date: datetime, end_date: datetime) -> int:
        logging.info(f"Getting denominator for {chain_id} {ad_scorer} {start_date} {end_date}")

        global LUABASE_CACHE_L1

        for i in range(0, 48):  # 48 hours; looking back if there are any values populated and return the most recent one
            cache_key = f"{chain_id}-{ad_scorer}-{(start_date-datetime.timedelta(hours=i)).strftime('%Y-%m-%dT%H')}"
            if cache_key in LUABASE_CACHE_L1.keys():
                logging.info(f"Got denominator for {chain_id} {ad_scorer} {(start_date-datetime.timedelta(hours=i))} {end_date}: {LUABASE_CACHE_L1[cache_key]}")
                return LUABASE_CACHE_L1[cache_key]

        raise ValueError(f"Denominator not found for {chain_id} {ad_scorer} {start_date} {end_date} in cache")

    def get_alert_count(self, chain_id: int, bot_id: str, alert_id: str, start_date: datetime, end_date: datetime) -> int:
        global LUABASE_CACHE_L1
        logging.info(f"Getting alert count for {chain_id} {bot_id} {alert_id} {start_date} {end_date}")

        for i in range(0, 48):  # 48 hours; looking back if there are any values populated and return the most recent one
            cache_key = f"{chain_id}-{bot_id}-{alert_id}-{(start_date-datetime.timedelta(hours=i)).strftime('%Y-%m-%dT%H')}"
            if cache_key in LUABASE_CACHE_L1.keys():
                logging.info(f"Got alert count for {chain_id} {bot_id} {alert_id} {(start_date-datetime.timedelta(hours=i))} {end_date}: {LUABASE_CACHE_L1[cache_key]}")
                return LUABASE_CACHE_L1[cache_key]

        raise ValueError(f"Alert count not found for {chain_id} {bot_id} {alert_id} {start_date} {end_date} in cache")

    def populate_denominator_cache(self, chain_id: int, ad_scorer: str, start_date: datetime, end_date: datetime):
        chain_name = Luabase.get_chain_name(chain_id)

        if start_date.hour % LUABASE_QUERY_FREQUENCY_IN_HOURS != 0 and LOCAL_NODE == 0:
            return

        sql = ""
        cache_key = f"{chain_id}-{ad_scorer}-{start_date.strftime('%Y-%m-%dT%H')}"
        if cache_key in LUABASE_CACHE_L1.keys():
            return

        value = L2Cache.load(chain_id, cache_key)
        if value is not None:
            LUABASE_CACHE_L1[cache_key] = int(value)
            return

        logging.info(f"Populating denominator cache for {chain_id} {ad_scorer} {start_date} {end_date}")

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

        try:
            value = Luabase().execute_query(sql)
            LUABASE_CACHE_L1[cache_key] = 1 if value.iloc[0]['uniqExact(hash)'] == 0 else value.iloc[0]['uniqExact(hash)']
            L2Cache.write(LUABASE_CACHE_L1[cache_key], chain_id, cache_key)
            logging.info(f"Populated denominator cache for {chain_id} {ad_scorer} {start_date} {end_date}: {LUABASE_CACHE_L1[cache_key]}")
        except Exception as e:
            logging.error(f"Failed to populate denominator cache for {chain_id} {ad_scorer} {start_date} {end_date}: {e}")

    def populate_alert_count_cache(self, chain_id: int, bot_id: str, alert_id: str, start_date: datetime, end_date: datetime):
        global LUABASE_CACHE_L1
        chain_name = Luabase.get_chain_name(chain_id)

        if start_date.hour % LUABASE_QUERY_FREQUENCY_IN_HOURS != 0 and LOCAL_NODE == 0:
            return

        sql = f"select COUNT(DISTINCT alert_hash) from forta.{chain_name}_alerts WHERE CAST(substring(block_timestamp,1,19) as datetime)  >= '{start_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND CAST(substring(block_timestamp,1,19)  as datetime)  <= '{end_date.strftime('%Y-%m-%dT%H:%M:%S')}' AND bot_id = '{bot_id}' AND alert_id = '{alert_id}'"
        cache_key = f"{chain_id}-{bot_id}-{alert_id}-{start_date.strftime('%Y-%m-%dT%H')}"
        if cache_key in LUABASE_CACHE_L1.keys():
            return

        value = L2Cache.load(chain_id, cache_key)
        if value is not None:
            LUABASE_CACHE_L1[cache_key] = int(value)
            return

        logging.info(f"Populating alert count cache for {chain_id} {bot_id} {alert_id} {start_date} {end_date}")
        try:
            value = Luabase().execute_query(sql)
            logging.info(value)            
            LUABASE_CACHE_L1[cache_key] = 1 if value.iloc[0]['uniqExact(alert_hash)'] == 0 else value.iloc[0]['uniqExact(alert_hash)']
            L2Cache.write(LUABASE_CACHE_L1[cache_key], chain_id, cache_key)
            logging.info(f"Populated alert count cache for {chain_id} {bot_id} {alert_id} {start_date} {end_date}: {LUABASE_CACHE_L1[cache_key]}")
        except Exception as e:
            logging.error(f"Failed to populate alert count cache for {chain_id} {bot_id} {alert_id} {start_date} {end_date}: {e}")

    def populate_cache(self, chain_id: int, start_date: datetime, end_date: datetime):
        global MUTEX_LUABASE

        if not MUTEX_LUABASE:
            try:
                MUTEX_LUABASE = True

                logging.debug(f"Populating luabase cache {start_date}")

                ad_scorers = ['contract-creation', 'contract-interactions', 'tx-count', 'transfer-in', 'transfer-out-large-amount', 'data-eoa-to', 'erc-approvalAll', 'erc-approvals', 'erc-transfers']
                for ad_scorer in ad_scorers:
                    self.populate_denominator_cache(chain_id, ad_scorer, start_date, end_date)

                for bot_id, alert_id, stage, ad_scorer in BASE_BOTS:
                    self.populate_alert_count_cache(chain_id, bot_id, alert_id, start_date, end_date)

                while len(LUABASE_CACHE_L1) > MAX_LUA_CACHE_SIZE:
                    logging.info(f"Removing item from luabase cache. Size: {len(LUABASE_CACHE_L1)}")
                    LUABASE_CACHE_L1.pop(next(iter(LUABASE_CACHE_L1)))

                logging.debug(f"Populated luabase cache {start_date}")
                MUTEX_LUABASE = False
            except Exception as e:
                logging.error(f"Failed to populate luabase cache {start_date}: {e}")
                MUTEX_LUABASE = False
        else:
            logging.debug("Populating luabase cache called, but mutex set. Exiting.")
