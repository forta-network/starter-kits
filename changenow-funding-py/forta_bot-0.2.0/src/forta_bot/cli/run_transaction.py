from typing import Callable
from web3 import AsyncWeb3
from ..common import ScanEvmOptions
from ..handlers import RunHandlersOnTransaction

RunTransaction = Callable[[str, ScanEvmOptions, AsyncWeb3.AsyncHTTPProvider, int], None]

def provide_run_transaction(run_handlers_on_transaction: RunHandlersOnTransaction):

  async def run_transaction(tx_hash: str, options: ScanEvmOptions, provider: AsyncWeb3.AsyncHTTPProvider, network_id: int) -> None:
    tx_hashes = [tx_hash]
    # support for specifying multiple transactions with comma-delimited list
    if tx_hash.find(",") >= 0:
      tx_hashes = tx_hash.split(",")

    for hash in tx_hashes:
      await run_handlers_on_transaction(hash, options, provider, network_id)

  return run_transaction