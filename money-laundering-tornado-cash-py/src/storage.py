import forta_agent
import json
import requests
import os

owner_db = "https://research.forta.network/database/owner/"
bucket_name = "prod-research-bot-data"
dynamo_table_name = "prod-research-bot-data"


test_mode = "main" if 'NODE_ENV' in os.environ and 'production' in os.environ.get(
    'NODE_ENV') else "test"


def _token():
    tk = forta_agent.fetch_jwt({})
    return {"Authorization": f"Bearer {tk}"}


def _load_json(key: str) -> object:
    if test_mode == "test":
        # loading json from local file secrets.json
        with open("secrets.json") as f:
            return json.load(f)
    else:
        res = requests.get(f"{owner_db}{key}", headers=_token())
        if res.status_code == 200:
            return res.json()
        else:
            raise Exception(
                f"error loading json from owner db: {res.status_code}, {res.text}")


def get_secrets():
    return _load_json("secrets.json")

