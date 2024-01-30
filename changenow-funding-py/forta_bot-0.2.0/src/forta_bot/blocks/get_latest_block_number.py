from typing import Callable
from web3 import AsyncWeb3

GetLatestBlockNumber = Callable[[AsyncWeb3.AsyncHTTPProvider], int]


def provide_get_latest_block_number():

  async def get_latest_block_number(provider: AsyncWeb3.AsyncHTTPProvider) -> int:
    return await provider.eth.block_number

  return get_latest_block_number