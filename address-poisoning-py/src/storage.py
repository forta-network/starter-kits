import forta_bot_sdk
import json
import aiohttp
import os

owner_db = "https://research.forta.network/database/owner/"

test_mode = "main" if 'FORTA_ENV' in os.environ and 'production' in os.environ.get(
    'FORTA_ENV') else "test"


async def _token():
    tk = await forta_bot_sdk.fetch_jwt()
    return {"Authorization": f"Bearer {tk}"}


async def _load_json_from_file(key: str) -> object:
    with open(key) as f:
        return json.load(f)


async def _load_json_from_db(key: str) -> object:
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{owner_db}{key}", headers=await _token()) as res:
            if res.status == 200:
                try:
                    return await res.json(content_type=None)
                except json.JSONDecodeError:
                    raise Exception("Failed to decode JSON response")
            else:
                raise Exception(
                    f"error loading json from owner db: {res.status}, {await res.text()}")


async def _load_json(key: str) -> object:
    if test_mode == "test":
        return await _load_json_from_file(key)
    else:
        return await _load_json_from_db(key)


async def get_secrets():
    return await _load_json("secrets.json")
