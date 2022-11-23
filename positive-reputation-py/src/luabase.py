import datetime
import requests
import pandas as pd
import os
from dotenv import load_dotenv
load_dotenv()


class Luabase:
    def execute_query(self, sql: str) -> pd.DataFrame:
        url = "https://q.luabase.com/run"
        payload = {
            "block": {
                "details": {
                    "sql": sql,
                }
            },
            "api_key": os.environ.get('LUABASE_API_KEY')
        }

        headers = {"content-type": "application/json"}
        response = requests.request("POST", url, json=payload, headers=headers)
        data = response.json()
        return pd.DataFrame(data["data"])

    def get_first_tx(self, address: str) -> datetime:
        sql = f"SELECT block_timestamp FROM ethereum.transactions WHERE from_address = '{address.lower()}' AND nonce == 0"
        value = Luabase().execute_query(sql)
        return datetime.datetime.strptime(value.iloc[0]['block_timestamp'], '%Y-%m-%dT%H:%M:%S')
