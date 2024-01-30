from ..utils import format_address

class Log:
    def __init__(self, dict):
        self.address: str = format_address(dict.get('address'))
        self.topics: list[str] = dict.get('topics', [])
        self.data: str = dict.get('data')
        self.log_index: int = dict.get('log_index', dict.get('logIndex'))
        self.block_number: int = dict.get('block_number', dict.get('blockNumber'))
        self.block_hash: str = dict.get('block_hash', dict.get('blockHash'))
        self.transaction_index: int = dict.get('transaction_index', dict.get('transactionIndex'))
        self.transaction_hash: str = dict.get('transaction_hash', dict.get('transactionHash'))
        self.removed: bool = dict.get('removed')