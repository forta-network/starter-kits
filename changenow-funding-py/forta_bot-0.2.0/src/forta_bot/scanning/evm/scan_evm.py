from datetime import datetime
from typing import Callable, Optional
from ...findings import Finding
from ...utils import GetBotId, Sleep
from ...cli import RunCliCommand
from ...blocks import GetLatestBlockNumber
from ...alerts import SendAlerts
from ...utils import GetNetworkId
from ...handlers import RunHandlersOnBlock
from ...common import ScanEvmOptions
from ..should_submit_findings import ShouldSubmitFindings
from ..should_stop_on_errors import ShouldStopOnErrors
from .get_provider import GetProvider

ScanEvm = Callable[[ScanEvmOptions], None]

def provide_scan_evm(
    get_bot_id: GetBotId,
    get_provider: GetProvider,
    get_network_id: GetNetworkId,
    is_running_cli_command: bool,
    run_cli_command: RunCliCommand,
    get_latest_block_number: GetLatestBlockNumber,
    run_handlers_on_block: RunHandlersOnBlock,
    send_alerts: SendAlerts,
    should_submit_findings: ShouldSubmitFindings,
    should_stop_on_errors: ShouldStopOnErrors,
    sleep: Sleep,
    forta_chain_id: Optional[int],
    forta_shard_id: Optional[int],
    forta_shard_count: Optional[int],
    should_continue_polling: Callable = lambda: True
    ) -> ScanEvm:
  
  async def scan_evm(options: ScanEvmOptions) -> None:
    if options.get('handle_block') is None and options.get('handle_transaction') is None:
      raise Exception("no block/transaction handler provided")
    
    bot_id = get_bot_id()
    provider = await get_provider(options)
    network_id = await get_network_id(provider)

    # if running a cli command, then dont start scanning
    if is_running_cli_command:
      await run_cli_command({'scan_evm_options': options, 'provider': provider, 'network_id': network_id})
      return

    # if scanning for a specific chain and its not this one, dont do anything
    if forta_chain_id is not None and forta_chain_id != network_id:
      return

    print(f'listening for data on chain {network_id}...')
    last_submission_timestamp = datetime.now() # initialize to now
    block_time_seconds = get_block_time(network_id)
    current_block_number: Optional(int) = None
    findings: list[Finding] = []

    # poll for latest blocks
    while(should_continue_polling()):
      # get_provider checks for expired RPC JWTs (so we call it often)
      provider = await get_provider(options)
      latest_block_number = await get_latest_block_number(provider)
      if current_block_number is None:
        current_block_number = latest_block_number

      # if no new blocks
      if (current_block_number > latest_block_number):
        # wait for a bit
        await sleep(block_time_seconds)
      else:
        # process new blocks
        while current_block_number <= latest_block_number:
          # check if this block should be processed
          if is_block_on_this_shard(current_block_number, forta_shard_id, forta_shard_count):
            # process block
            findings.extend(await run_handlers_on_block(current_block_number, options, provider, network_id, should_stop_on_errors()))
          current_block_number += 1

      # check if should submit any findings
      if should_submit_findings(findings, last_submission_timestamp):
        await send_alerts([{'bot_id': bot_id, 'finding': f} for f in findings])
        findings = [] # clear array
        last_submission_timestamp = datetime.now() # remember timestamp

  return scan_evm

# returns block time in seconds given a chain id
def get_block_time(network_id: int) -> int:
  match network_id:
    case 137: # polygon
      return 3
    case 56: # bsc
      return 5
    case 43114: # avalanche
      return 3
    case 250: # fantom
      return 5
    case 8453: # base
      return 2
    case _:
      return 15

def is_block_on_this_shard(block_number: int, shard_id: Optional[int], shard_count: Optional[int]) -> bool:
  # if bot is not sharded
  if shard_id is None or shard_count is None:
    return True # process everything
  
  # process block if block_number modulo shard_count equals shard_id
  return block_number % shard_count == shard_id