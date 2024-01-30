from typing import Callable
from web3 import AsyncWeb3
from ..utils import assert_exists
from ..common import ScanEvmOptions
from ..handlers import RunHandlersOnBlock

RunBlock = Callable[[str, ScanEvmOptions, AsyncWeb3.AsyncHTTPProvider, int], None]

def provide_run_block(run_handlers_on_block: RunHandlersOnBlock):
  assert_exists(run_handlers_on_block, 'run_handlers_on_block')

  async def run_block(block_number_or_hash: str, options: ScanEvmOptions, provider: AsyncWeb3.AsyncHTTPProvider, network_id: int) -> None:
    blocks = [block_number_or_hash]
    # support for specifying multiple blocks with comma-delimited list
    if block_number_or_hash.find(",") >= 0:
      blocks = block_number_or_hash.split(",")

    for block in blocks:
      await run_handlers_on_block(block, options, provider, network_id)

  return run_block