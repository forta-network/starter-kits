import json
from typing import Callable
from web3 import AsyncWeb3


GetTraceData = Callable[[str | int, AsyncWeb3.AsyncHTTPProvider, int], list[dict]]

def provide_get_trace_data():

  async def get_trace_data(block_number_or_tx_hash: str | int, provider: AsyncWeb3.AsyncHTTPProvider, network_id: int) -> list[dict]:
    # TODO check cache

    # fetch trace data
    try:
      is_block_number = isinstance(block_number_or_tx_hash, int)
      if is_block_number:
        trace_data = await provider.tracing.trace_block(hex(block_number_or_tx_hash))
      else:
        trace_data = await provider.tracing.trace_transaction(block_number_or_tx_hash)

      # TODO write to cache
      return json.loads(provider.to_json(trace_data))
    except Exception as e:
      print(f'error getting trace data: {e}')
    
    return []
  
  return get_trace_data