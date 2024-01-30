from typing import Optional
from ..utils import hex_to_int
from ..logs import Log

class Receipt:
    def __init__(self, dict):
        self.status: bool = dict.get('status')
        self.root: str = dict.get('root')
        self.gas_used: int = hex_to_int(dict.get('gas_used'))
        self.cumulative_gas_used: int = hex_to_int(dict.get('cumulative_gas_used'))
        self.logs_bloom: str = dict.get('logs_bloom')
        self.logs: list[Log] = list(map(lambda t: Log(t), dict.get('logs', [])))
        self.contract_address: Optional[str] = dict.get('contract_address')
        self.block_number: int = dict.get('block_number')
        self.block_hash: str = dict.get('block_hash')
        self.transaction_index: int = dict.get('transaction_index')
        self.transaction_hash: str = dict.get('transaction_hash')