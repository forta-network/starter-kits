from typing import Callable
from ..logs import Log
from ..utils import format_address
from ..traces import Trace
from .transaction_event import TransactionEvent

CreateTransactionEvent = Callable[[dict, dict, int, list[Trace], list[Log]], TransactionEvent]


def provide_create_transaction_event():

  def create_transaction_event(transaction: dict, block: dict, network_id: int, traces: list[Trace] = [], logs: list[Log] = []):
    if traces is None: traces = []
    if logs is None: logs = []
    
    # build map of addresses involved in transaction
    addresses = {}
    addresses[format_address(transaction['from'])] = True
    if transaction.get('to') is not None: addresses[format_address(transaction['to'])] = True
    for trace in traces:
      if trace.action.address is not None: addresses[trace.action.address] = True
      if trace.action.refund_address is not None: addresses[trace.action.refund_address] = True
      if trace.action.to is not None: addresses[trace.action.to] = True
      if trace.action.from_ is not None: addresses[trace.action.from_] = True
    for log in logs:
      addresses[log.address] = True

    # TODO calculate contract create address
    # let contractAddress = null;
    # if (isZeroAddress(transaction.to)) {
    #   contractAddress = formatAddress(
    #     getCreateAddress({ from: transaction.from, nonce: transaction.nonce })
    #   );
    # }
    # https://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed
    # https://stackoverflow.com/questions/76293617/how-to-pre-generate-an-ethereum-contract-adress

    return TransactionEvent({
      'network': network_id,
      'transaction': transaction,
      'block': block,
      'traces': traces,
      'logs': logs,
      'addresses': addresses,
      'contract_address': None
    })

  return create_transaction_event