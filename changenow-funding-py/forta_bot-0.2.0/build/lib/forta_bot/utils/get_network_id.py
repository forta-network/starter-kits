from typing import Callable
from web3 import AsyncWeb3

GetNetworkId = Callable[[AsyncWeb3.AsyncHTTPProvider], int]

def provide_get_network_id() -> GetNetworkId:

  async def get_network_id(provider: AsyncWeb3.AsyncHTTPProvider) -> int:
    return int(await provider.eth.chain_id)
  
  return get_network_id