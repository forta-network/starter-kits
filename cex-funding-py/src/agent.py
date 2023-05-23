from os import environ
import forta_agent
from hexbytes import HexBytes
from forta_agent import get_json_rpc_url
from src.constants import CEXES
from web3 import Web3

from src.findings import CEXFundingFinding
from src.keys import ZETTABLOCK_KEY

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


def initialize():
    environ["ZETTABLOCK_API_KEY"] = ZETTABLOCK_KEY


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes("0x")


def detect_dex_funding(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    findings = []

    # alert on funding tx from CEXes
    if transaction_event.transaction.to is not None:
        value = transaction_event.transaction.value
        for chainId, address, name, threshold in CEXES:
            if chainId == w3.eth.chain_id:
                if w3.eth.get_transaction_count(
                    Web3.toChecksumAddress(transaction_event.transaction.to),
                    transaction_event.block.number,
                ) == 0 and not is_contract(w3, transaction_event.transaction.to):
                    if address == transaction_event.transaction.from_ and value < threshold:
                        findings.append(
                            CEXFundingFinding(
                                name, transaction_event.transaction.to, value, chainId
                            ).emit_finding()
                        )

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(
        transaction_event: forta_agent.transaction_event.TransactionEvent,
    ) -> list:
        return detect_dex_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
