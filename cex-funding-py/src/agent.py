import forta_agent
from hexbytes import HexBytes
from forta_agent import Finding, FindingType, FindingSeverity, get_json_rpc_url
from src.constants import CEXES
from web3 import Web3

from src.findings import CEXFundingFinding

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

ALERT_COUNT = 0  # stats to emit anomaly score
DENOMINATOR_COUNT = 0  # stats to emit anomaly score

def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global DENOMINATOR_COUNT
    DENOMINATOR_COUNT = 0

    global ALERT_COUNT
    ALERT_COUNT = 0

def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')

def detect_dex_funding(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    findings = []

    global ALERT_COUNT
    global DENOMINATOR_COUNT

    # alert on funding tx from CEXes
    value = transaction_event.transaction.value
    for chainId, address, name, threshold in CEXES:
        if chainId == w3.eth.chainId:
            if (w3.eth.get_transaction_count(Web3.toChecksumAddress(transaction_event.transaction.to), transaction_event.block.number) == 0
                and not is_contract(w3, transaction_event.transaction.to)):
                DENOMINATOR_COUNT += 1
                if (address == transaction_event.transaction.from_ and value < threshold):
                    ALERT_COUNT += 1
                    anomaly_score = (ALERT_COUNT * 1.0) / DENOMINATOR_COUNT
                    findings.append(CEXFundingFinding.cex_funding(name, transaction_event.transaction.to, value, anomaly_score))
                
    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_dex_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)