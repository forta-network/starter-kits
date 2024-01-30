import json
from typing import Callable
from web3 import AsyncWeb3

GetLogsForBlock = Callable[[int, AsyncWeb3.AsyncHTTPProvider, int], list[dict]]


def provide_get_logs_for_block() -> GetLogsForBlock:

  async def get_logs_for_block(block_number: int, provider: AsyncWeb3.AsyncHTTPProvider, network_id: int) -> list[dict]:
    # TODO check cache

    block_number_hex = hex(block_number)
    logs = await provider.eth.get_logs({'fromBlock': block_number_hex, 'toBlock': block_number_hex})

    # TODO write to cache
    return json.loads(provider.to_json(logs))

  return get_logs_for_block