import os
import asyncio
from typing import Callable, Optional, TypedDict
from web3 import AsyncWeb3
from ..utils import assert_exists, GetAioHttpSession
from ..common import ScanEvmOptions
from .run_transaction import RunTransaction
from .run_block import RunBlock
from .run_alert import RunAlert
from .run_block_range import RunBlockRange

class RunCliCommandOptions(TypedDict):
  scan_evm_options: Optional[ScanEvmOptions]
  provider: Optional[AsyncWeb3.AsyncHTTPProvider]
  network_id: Optional[int]
  scan_alerts_options: Optional[object]

RunCliCommand = Callable[[RunCliCommandOptions], None]

def provide_run_cli_command(
    get_aiohttp_session: GetAioHttpSession,
    run_transaction: RunTransaction,
    run_block: RunBlock,
    run_alert: RunAlert,
    run_block_range: RunBlockRange
    # run_sequence: RunSequence,
    # run_file: RunFile
) -> RunCliCommand:

  async def run_cli_command(options: RunCliCommandOptions) -> None:
    scan_evm_options = options.get('scan_evm_options')
    provider = options.get('provider')
    network_id = options.get('network_id')
    scan_alerts_options = options.get('scan_alerts_options')

    FORTA_CHAIN_ID = os.environ.get('FORTA_CHAIN_ID')
    FORTA_CLI_TX = os.environ.get('FORTA_CLI_TX')
    FORTA_CLI_BLOCK = os.environ.get('FORTA_CLI_BLOCK')
    FORTA_CLI_ALERT = os.environ.get('FORTA_CLI_ALERT')
    FORTA_CLI_RANGE = os.environ.get('FORTA_CLI_RANGE')
    FORTA_CLI_SEQUENCE = os.environ.get('FORTA_CLI_SEQUENCE')
    FORTA_CLI_FILE = os.environ.get('FORTA_CLI_FILE')

    # need to specify chainId if running block/tx/range
    if FORTA_CLI_BLOCK or FORTA_CLI_TX or FORTA_CLI_RANGE:
      assert_exists(FORTA_CHAIN_ID, 'chainId')

    if FORTA_CLI_TX and is_correct_chain_id(FORTA_CHAIN_ID, network_id):
      await run_transaction(FORTA_CLI_TX, scan_evm_options, provider, network_id)
      await cleanup(get_aiohttp_session)
    elif FORTA_CLI_BLOCK and is_correct_chain_id(FORTA_CHAIN_ID, network_id):
      await run_block(FORTA_CLI_BLOCK, scan_evm_options, provider, network_id)
      await cleanup(get_aiohttp_session)
    elif FORTA_CLI_RANGE and is_correct_chain_id(FORTA_CHAIN_ID, network_id):
      await run_block_range(FORTA_CLI_RANGE, scan_evm_options, provider, network_id)
      await cleanup(get_aiohttp_session)
    elif FORTA_CLI_ALERT and scan_alerts_options:
      await run_alert(FORTA_CLI_ALERT, scan_alerts_options)
      await cleanup(get_aiohttp_session)
    elif FORTA_CLI_SEQUENCE:
      raise Exception("sequence command not implemented yet")
    elif FORTA_CLI_FILE:
      raise Exception("file command not implemented yet")

  return run_cli_command


def is_correct_chain_id(forta_chain_id: str, network_id: int):
  return forta_chain_id and network_id and int(forta_chain_id) == network_id

async def cleanup(get_aiohttp_session: GetAioHttpSession):
    # clean up the aiohttp session (otherwise it throws an ugly error on process completion)
    # https://docs.aiohttp.org/en/stable/client_advanced.html#graceful-shutdown
    session = await get_aiohttp_session()
    await asyncio.sleep(0.25)
    await session.close()