import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3

from src.constants import BLOCK_RANGE, TORNADO_CASH_ADDRESSES, TORNADO_CASH_DEPOSIT_SIZE, TORNADO_CASH_DEPOSIT_SIZE_MATIC, TORNADO_CASH_ROUTER_ADDRESS, TORNADO_CASH_DEPOSIT_TOPIC, TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_BSC, TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_ETH, TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_MATIC, TORNADO_CASH_ACCOUNTS_QUEUE_SIZE
from src.findings import MoneyLaunderingTornadoCashFindings

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

ACCOUNT_TO_TORNADO_CASH_BLOCKS = {}  # dict of accounts to dicts of blocks to counts; e.g. # account 1, block 101, 1
ACCOUNT_QUEUE = []


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global ACCOUNT_TO_TORNADO_CASH_BLOCKS
    ACCOUNT_TO_TORNADO_CASH_BLOCKS = {}

    global ACCOUNT_QUEUE
    ACCOUNT_QUEUE = []


def detect_money_laundering(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global ACCOUNT_TO_TORNADO_CASH_BLOCKS
    global ACCOUNT_QUEUE

    findings = []
    account = Web3.toChecksumAddress(transaction_event.from_)

    if transaction_event.to is None:
        return findings

    if Web3.toChecksumAddress(transaction_event.to) == TORNADO_CASH_ROUTER_ADDRESS:
        for log in transaction_event.logs:
            if (transaction_event.transaction.value is not None and transaction_event.transaction.value > 0 and
               Web3.toChecksumAddress(log.address) == TORNADO_CASH_ADDRESSES[w3.eth.chain_id] and TORNADO_CASH_DEPOSIT_TOPIC in log.topics):

                ACCOUNT_QUEUE.append(account)

                block_to_tx_count = {}
                if account not in ACCOUNT_TO_TORNADO_CASH_BLOCKS:
                    ACCOUNT_TO_TORNADO_CASH_BLOCKS[account] = block_to_tx_count
                else:
                    block_to_tx_count = ACCOUNT_TO_TORNADO_CASH_BLOCKS[account]

                if transaction_event.block_number not in block_to_tx_count.keys():
                    block_to_tx_count[transaction_event.block_number] = 1
                else:
                    block_to_tx_count[transaction_event.block_number] += 1

                #  maintain a size
                if len(ACCOUNT_QUEUE) > TORNADO_CASH_ACCOUNTS_QUEUE_SIZE:
                    acc = ACCOUNT_QUEUE.pop(0)
                    ACCOUNT_TO_TORNADO_CASH_BLOCKS.pop(acc, None)

                while max(block_to_tx_count.keys()) - min(block_to_tx_count.keys()) > BLOCK_RANGE:
                    #  remove the oldest blocks
                    oldest_block = min(block_to_tx_count, key=block_to_tx_count.get)
                    block_to_tx_count.pop(oldest_block, None)

    if account in ACCOUNT_QUEUE:
        total_txs = sum(ACCOUNT_TO_TORNADO_CASH_BLOCKS[account].values())

        tx_threshold = TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_ETH
        deposit_size = TORNADO_CASH_DEPOSIT_SIZE
        if w3.eth.chain_id == 137:
            tx_threshold = TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_MATIC
            deposit_size = TORNADO_CASH_DEPOSIT_SIZE_MATIC
        if w3.eth.chain_id == 56:
            tx_threshold = TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_BSC

        if total_txs >= tx_threshold:
            findings.append(MoneyLaunderingTornadoCashFindings.possible_money_laundering_tornado_cash(account, total_txs * deposit_size))

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_money_laundering(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
