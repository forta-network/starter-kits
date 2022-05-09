import forta_agent
import rlp
from findings import UnverifiedCodeContractFindings
from forta_agent import get_json_rpc_url
from constants import ETHERSCAN_API_KEY
from etherscan import Etherscan
from web3 import Web3

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
etherscan = Etherscan(ETHERSCAN_API_KEY)


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def detect_unverified_contract_creation(w3, etherscan, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    findings = []

    created_contract_addresses = []
    for trace in transaction_event.traces:
        if trace.type == 'create':
            if (transaction_event.from_ == trace.action.from_ or trace.action.from_ in created_contract_addresses):

                nonce = transaction_event.transaction.nonce if transaction_event.from_ == trace.action.from_ else 1  # for contracts creating other contracts, the nonce would be 1
                created_contract_address = calc_contract_address(w3, trace.action.from_, nonce)
                if not etherscan.is_verified(created_contract_address):
                    findings.append(UnverifiedCodeContractFindings.unverified_code(trace.action.from_, created_contract_address))

    return findings


def provide_handle_transaction(w3, etherscan):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_unverified_contract_creation(w3, etherscan, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3, etherscan)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
