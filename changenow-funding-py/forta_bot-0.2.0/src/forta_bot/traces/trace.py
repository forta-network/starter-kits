from ..utils import hex_to_int, format_address

class Trace:
    def __init__(self, dict):
        self.action: TraceAction = TraceAction(dict.get('action', {}))
        self.block_hash: str = dict.get('block_hash', dict.get('blockHash'))
        self.block_number: int = dict.get('block_number', dict.get('blockNumber'))
        self.result: TraceResult = TraceResult(dict.get('result', {}))
        self.subtraces: int = dict.get('subtraces')
        self.trace_address: list[int] = dict.get('trace_address', dict.get('traceAddress', []))
        self.transaction_hash: str = dict.get('transaction_hash', dict.get('transactionHash'))
        self.transaction_position: int = dict.get('transaction_position', dict.get('transactionPosition'))
        self.type: str = dict.get('type')
        self.error: str = dict.get('error')

class TraceAction:
    def __init__(self, dict):
        self.call_type: str = dict.get('call_type', dict.get('callType'))
        self.to: str = format_address(dict.get('to'))
        self.input: str = dict.get('input')
        self.from_: str = format_address(dict.get('from'))
        self.value: int = hex_to_int(dict.get('value'))
        self.init: str = dict.get('init')
        self.address: str = format_address(dict.get('address'))
        self.balance: str = dict.get('balance')
        self.refund_address: str = format_address(dict.get('refund_address', dict.get('refundAddress')))

class TraceResult:
    def __init__(self, dict):
        self.gas_used: int = hex_to_int(dict.get('gas_used', dict.get('gasUsed')))
        self.address: str = dict.get('address')
        self.code: str = dict.get('code')
        self.output: str = dict.get('output')
