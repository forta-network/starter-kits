import asyncio
from typing import Callable
from web3 import AsyncWeb3
from ..utils import assert_exists
from ..findings import Finding
from ..transactions import CreateTransactionEvent, GetTransactionReceipt
from ..blocks import GetBlockWithTransactions
from ..traces import Trace, GetTraceData
from ..logs import Log
from ..common import ScanEvmOptions

RunHandlersOnTransaction = Callable[[str, ScanEvmOptions, AsyncWeb3.AsyncHTTPProvider, int], list[Finding]]


def provide_run_handlers_on_transaction(
    get_transaction_receipt: GetTransactionReceipt,
    get_block_with_transactions: GetBlockWithTransactions,
    get_trace_data: GetTraceData,
    create_transaction_event: CreateTransactionEvent
) -> RunHandlersOnTransaction:
  assert_exists(get_transaction_receipt, 'get_transaction_receipt')
  assert_exists(get_block_with_transactions, 'get_block_with_transactions')
  assert_exists(get_trace_data, 'get_trace_data')
  assert_exists(create_transaction_event, 'create_transaction_event')

  async def run_handlers_on_transaction(tx_hash: str, options: ScanEvmOptions, provider: AsyncWeb3.AsyncHTTPProvider, network_id: int) -> list[Finding]:
    handle_transaction = options.get('handle_transaction')
    if not handle_transaction:
      raise Exception("no transaction handler provided")
    
    coroutines = [get_transaction_receipt(tx_hash, provider, network_id)]
    if options.get('use_trace_data') == True:
      coroutines.append(get_trace_data(tx_hash, provider, network_id))
    receipt_and_traces = await asyncio.gather(*coroutines)
  
    receipt = receipt_and_traces[0]
    if not receipt:
      print(f'no transaction found for hash {tx_hash} on chain {network_id}')
      return []
    
    block = await get_block_with_transactions(receipt['blockNumber'], provider, network_id)
    tx_hash = tx_hash.lower()
    for tx in block['transactions']:
      if tx['hash'].lower() == tx_hash:
        transaction = tx
    traces = receipt_and_traces[1] if len(receipt_and_traces) > 1 else []
    traces = [Trace(t) for t in traces]
    logs = [Log(l) for l in receipt['logs']]
    transaction_event = create_transaction_event(transaction, block, network_id, traces, logs)
    findings = await handle_transaction(transaction_event, provider)

    # TODO assert_findings(findings)
    print(f'{len(findings)} findings for transaction {tx_hash} on chain {network_id} {findings if len(findings) > 0 else ""}')

    return findings


  return run_handlers_on_transaction