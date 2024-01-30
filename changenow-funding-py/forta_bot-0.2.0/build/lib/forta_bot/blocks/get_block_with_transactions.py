import json
from web3 import AsyncWeb3
from typing import Callable


GetBlockWithTransactions = Callable[[str | int, AsyncWeb3.AsyncHTTPProvider, int], dict]

def provide_get_block_with_transactions() -> GetBlockWithTransactions:

  async def get_block_with_transactions(block_hash_or_number: str | int, provider: AsyncWeb3.AsyncHTTPProvider, network_id: int) -> dict:
    # TODO check cache

    # fetch the block with transactions
    block = await provider.eth.get_block(block_hash_or_number, True)

    # TODO write to cache
    return json.loads(provider.to_json(block))
  
  return get_block_with_transactions