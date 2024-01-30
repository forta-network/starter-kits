from ..utils import format_address

class Block:
    def __init__(self, dict):
        self.difficulty: int = dict.get('difficulty')
        self.extra_data: str = dict.get('extra_data', dict.get('extraData'))
        self.gas_limit: int = dict.get('gas_limit', dict.get('gasLimit'))
        self.gas_used: int = dict.get('gas_used', dict.get('gasUsed'))
        self.hash: str = dict.get('hash')
        self.logs_bloom: str = dict.get('logs_bloom', dict.get('logsBloom'))
        self.miner: str = format_address(dict.get('miner'))
        self.mix_hash: str = dict.get('mix_hash', dict.get('mixHash'))
        self.nonce: str = dict.get('nonce')
        self.number: int = dict.get('number')
        self.parent_hash: str = dict.get('parent_hash', dict.get('parentHash'))
        self.receipts_root: str = dict.get('receipts_root', dict.get('receiptsRoot'))
        self.sha3_uncles: str = dict.get('sha3_uncles', dict.get('sha3Uncles'))
        self.size: int = dict.get('size')
        self.state_root: str = dict.get('state_root', dict.get('stateRoot'))
        self.timestamp: int = dict.get('timestamp')
        self.total_difficulty: int = dict.get('total_difficulty', dict.get('totalDifficulty'))
        # determine whether given a list of transaction hashes or transaction objects
        transactions = dict.get('transactions')
        is_transaction_hashes = type(transactions) == list and len(transactions) > 0 and type(transactions[0]) == str
        if not is_transaction_hashes:
            # convert transaction objects to hashes
            transactions = [t.get('hash') for t in transactions]
        self.transactions: list[str] = transactions
        self.transactions_root: str = dict.get('transactions_root', dict.get('transactionsRoot'))
        self.uncles: list[str] = dict.get('uncles')