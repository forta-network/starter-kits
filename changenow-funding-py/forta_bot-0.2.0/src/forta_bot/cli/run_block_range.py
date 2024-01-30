from typing import Callable
from web3 import AsyncWeb3
from ..utils import assert_exists
from ..common import ScanEvmOptions
from ..handlers import RunHandlersOnBlock

RunBlockRange = Callable[[str, ScanEvmOptions, AsyncWeb3.AsyncHTTPProvider, int], None]

def provide_run_block_range(run_handlers_on_block: RunHandlersOnBlock):
  assert_exists(run_handlers_on_block, 'run_handlers_on_block')

  async def run_block_range(block_range: str, options: ScanEvmOptions, provider: AsyncWeb3.AsyncHTTPProvider, network_id: int) -> None:
    start_block, end_block = block_range.split("..")
    start_block_number = int(start_block)
    end_block_number = int(end_block)
    if end_block_number <= start_block_number:
      raise Exception("end block must be greater than start block")

    for block_number in range(start_block_number, end_block_number+1):
      await run_handlers_on_block(block_number, options, provider, network_id)

  return run_block_range