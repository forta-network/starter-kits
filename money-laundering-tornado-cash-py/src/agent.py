import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3

from src.constants import BLOCK_RANGE, TORNADO_CASH_ADDRESSES, TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_ETH, TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_MATIC, TORNADO_CASH_ACCOUNTS_QUEUE_SIZE
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
    processed_traces = []
    accounts_sending_funds = set()

    for trace in transaction_event.traces:
        if trace.transaction_position in processed_traces:
            continue

        if trace.action.to is None:
            continue

        account = Web3.toChecksumAddress(trace.action.to)
        if trace.action.value is not None and trace.action.value > 0 and Web3.toChecksumAddress(trace.action.from_) == TORNADO_CASH_ADDRESSES[w3.eth.chain_id]:
            processed_traces.append(trace.transaction_position) #  seems like some traces are repeated, so we only want to process each trace once

            accounts_sending_funds.add(account)
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

    for account in accounts_sending_funds:
        total_txs = sum(ACCOUNT_TO_TORNADO_CASH_BLOCKS[account].values())
        tx_threshold = TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_MATIC if w3.eth.chain_id == 137 else TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_ETH
        if total_txs >= tx_threshold:
            findings.append(MoneyLaunderingTornadoCashFindings.possible_money_laundering_tornado_cash(account, total_txs))

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_money_laundering(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
