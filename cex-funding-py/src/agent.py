from os import environ
import forta_agent
from functools import lru_cache
from hexbytes import HexBytes
from forta_agent import get_json_rpc_url
from src.constants import CEXES
from web3 import Web3

from src.findings import CEXFundingFinding
from src.storage import get_secrets

SECRETS_JSON = get_secrets()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


def initialize():
    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']

@lru_cache(maxsize=1_000_000)
def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True

    checksum_address = Web3.toChecksumAddress(address)
    code = w3.eth.get_code(checksum_address)
    return code is not None and code != HexBytes("0x")


def detect_cex_funding(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    findings = []

    if transaction_event.transaction.to is not None:
        to_address_checksum = Web3.toChecksumAddress(transaction_event.transaction.to)

        # alert on funding tx from CEXes
        if w3.eth.get_transaction_count(to_address_checksum, transaction_event.block.number) == 0 and not is_contract(w3, to_address_checksum):
            value = transaction_event.transaction.value

            for chainId, chain_data in CEXES.items():
                if chainId == w3.eth.chainId:
                    threshold = chain_data["threshold"]
                    for address, name in chain_data["exchanges"]:
                        if address.lower() == transaction_event.transaction.from_ and value < threshold:
                            findings.append(
                                CEXFundingFinding(
                                    name, transaction_event.transaction.to, value, chainId
                                ).emit_finding()
                            )
                            break

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(
        transaction_event: forta_agent.transaction_event.TransactionEvent,
    ) -> list:
        return detect_cex_funding(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
