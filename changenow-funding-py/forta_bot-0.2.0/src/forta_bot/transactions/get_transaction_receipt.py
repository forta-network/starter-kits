import json
from typing import Callable
from web3 import AsyncWeb3

GetTransactionReceipt = Callable[[str, AsyncWeb3.AsyncHTTPProvider, int], dict]

def provide_get_transaction_receipt():

  async def get_transaction_receipt(tx_hash: str, provider: AsyncWeb3.AsyncHTTPProvider, network_id: int):
    # TODO check cache

    # fetch the receipt
    receipt = await provider.eth.get_transaction_receipt(tx_hash)

    # TODO write cache
    return json.loads(provider.to_json(receipt))
  
  return get_transaction_receipt