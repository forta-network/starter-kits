import json
from typing import Optional, TypedDict
from hexbytes import HexBytes
from ..logs import Log
from ..traces import Trace
from .transaction import Transaction


class TxEventBlock(TypedDict):
    hash: str
    number: int
    timestamp: int

class TransactionEvent:
    def __init__(self, dict):
        self.network: int = dict.get('network')
        self.transaction: Transaction = Transaction(dict.get('transaction', {}))
        self.traces: list[Trace] = list(map(lambda t: Trace(t) if not isinstance(t, Trace) else t, dict.get('traces', [])))
        self.addresses: dict[str, bool] = dict.get('addresses', {})
        self.block: TxEventBlock = dict.get('block', {})
        self.logs: list[Log] = list(map(lambda l: Log(l) if not isinstance(l, Log) else l, dict.get('logs', [])))
        self.contract_address: Optional[str] = dict.get('contract_address')

    @property
    def hash(self):
        return self.transaction.hash

    @property
    def to(self):
        return self.transaction.to

    @property
    def from_(self):
        return self.transaction.from_

    @property
    def gas_price(self):
        return self.transaction.gas_price

    @property
    def timestamp(self):
        return self.block.timestamp

    @property
    def block_number(self):
        return self.block.number

    @property
    def block_hash(self):
        return self.block.hash

    def filter_log(self, abi, contract_address=''):
        abi = abi if isinstance(abi, list) else [abi]
        abi = [json.loads(abi_item) for abi_item in abi]
        logs = self.logs
        # filter logs by contract address, if provided
        if (contract_address):
            contract_address = contract_address if isinstance(
                contract_address, list) else [contract_address]
            contract_address_map = {
                address.lower(): True for address in contract_address}
            logs = filter(lambda log: log.address.lower()
                          in contract_address_map, logs)
        # determine which event names to filter
        event_names = []
        for abi_item in abi:
            if abi_item['type'] == "event":
                event_names.append(abi_item['name'])
        # parse logs
        results = []
        from . import web3Provider
        contract = web3Provider.eth.contract(
            "0x0000000000000000000000000000000000000000", abi=abi)
        for log in logs:
            log.topics = [HexBytes(topic) for topic in log.topics]
            for event_name in event_names:
                try:
                    results.append(
                        contract.events[event_name]().processLog(log))
                except:
                    continue  # TODO see if theres a better way to handle 'no matching event' error
        return results

    def filter_function(self, abi, contract_address=''):
        abi = abi if isinstance(abi, list) else [abi]
        abi = [json.loads(abi_object) for abi_object in abi]
        # determine where to look for function calls (i.e. transaction object or traces)
        sources = [{'data': self.transaction.data, 'to': self.transaction.to}]
        if self.traces:
            sources = [{'data': trace.action.input,
                        'to': trace.action.to} for trace in self.traces]
        # filter by contract address, if provided
        if (contract_address):
            contract_address = contract_address if isinstance(
                contract_address, list) else [contract_address]
            contract_address_map = {
                address.lower(): True for address in contract_address}
            sources = filter(
                lambda source: source['to'] and source['to'].lower() in contract_address_map, sources)
        # parse function inputs
        results = []
        from . import web3Provider
        contract = web3Provider.eth.contract(
            "0x0000000000000000000000000000000000000000", abi=abi)
        for source in sources:
            try:
                decoded_function = contract.decode_function_input(
                    source['data'])
                decoded_function[1]["address"] = source['to'].lower()
                results.append(decoded_function)
            except:
                continue  # TODO see if theres a better way to handle 'no matching function' error
        return results
