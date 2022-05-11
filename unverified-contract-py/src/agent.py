import logging
import sys

import forta_agent
import rlp
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from pyevmasm import disassemble_hex
from web3 import Web3

from src.constants import CONTRACT_SLOT_ANALYSIS_DEPTH, ETHERSCAN_API_KEY
from src.etherscan import Etherscan
from src.findings import UnverifiedCodeContractFindings

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
etherscan = Etherscan(ETHERSCAN_API_KEY)


root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')


def get_storage_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the storage of a contract (first CONTRACT_SLOT_ANALYSIS_DEPTH slots)
    :return: address_list: list (only returning contract addresses)
    """
    if address is None:
        return set()

    address_set = set()
    for i in range(CONTRACT_SLOT_ANALYSIS_DEPTH):
        mem = w3.eth.get_storage_at(Web3.toChecksumAddress(address), i)
        if mem != HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000'):
            # looking at both areas of the storage slot as - depending on packing - the address could be at the beginning or the end.
            if is_contract(w3, mem[0:20]):
                address_set.add(Web3.toChecksumAddress(mem[0:20].hex()))
            if is_contract(w3, mem[12:]):
                address_set.add(Web3.toChecksumAddress(mem[12:].hex()))

    return address_set


def get_opcode_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the opcodes of a contract
    :return: address_list: list (only returning contract addresses)
    """
    if address is None:
        return set()

    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    opcode = disassemble_hex(code.hex())
    address_set = set()
    for op in opcode.splitlines():
        for param in op.split(' '):
            if param.startswith('0x') and len(param) == 42:
                if is_contract(w3, param):
                    address_set.add(Web3.toChecksumAddress(param))

    return address_set


def detect_unverified_contract_creation(w3, etherscan, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    findings = []

    logging.info(f"Scanning transaction {transaction_event.transaction.hash} on chain {w3.eth.chain_id}")

    created_contract_addresses = []
    for trace in transaction_event.traces:
        if trace.type == 'create':
            if (transaction_event.from_ == trace.action.from_ or trace.action.from_ in created_contract_addresses):

                nonce = transaction_event.transaction.nonce if transaction_event.from_ == trace.action.from_ else 1  # for contracts creating other contracts, the nonce would be 1
                created_contract_address = calc_contract_address(w3, trace.action.from_, nonce)
                if not etherscan.is_verified(created_contract_address):
                    logging.info(f"Identified unverified contract: {created_contract_address}")
                    storage_addresses = get_storage_addresses(w3, created_contract_address)
                    opcode_addresses = get_opcode_addresses(w3, created_contract_address)

                    findings.append(UnverifiedCodeContractFindings.unverified_code(trace.action.from_, created_contract_address, set.union(storage_addresses, opcode_addresses)))
                else:
                    logging.info(f"Identified verified contract: {created_contract_address}")

    return findings


def provide_handle_transaction(w3, etherscan):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_unverified_contract_creation(w3, etherscan, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3, etherscan)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
