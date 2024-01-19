import json
import os
import aiohttp

import forta_bot

owner_db = "https://research.forta.network/database/owner/"

test_mode = "main" if 'FORTA_ENV' in os.environ and 'production' in os.environ.get(
    'FORTA_ENV') else "test"

async def _token():
    tk = await forta_bot.fetch_jwt()
    return {"Authorization": f"Bearer {tk}"}

async def _load_json(key: str) -> object:
    if test_mode == "test":
        with open("secrets.json") as f:
            return json.load(f)
    else:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{owner_db}{key}", headers=await _token()) as res:
                if res.status_code == 200:
                    return await res.json()
                else:
                    raise Exception(
                        f"error loading json from owner db: {res.status_code}, {res.text}")

async def get_secrets():
    return await _load_json("secrets.json")
