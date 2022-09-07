import logging
import sys

import forta_agent
import numpy as np
import pandas as pd
import rlp
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from joblib import load
from pyevmasm import disassemble_hex
from web3 import Web3

from src.constants import (BYTE_CODE_LENGTH_THRESHOLD,
                           CONTRACT_SLOT_ANALYSIS_DEPTH, MODEL_THRESHOLD)
from src.findings import MaliciousContractFindings

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
model = load('model.joblib')
features = []

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global features
    features = open("features.txt").read().splitlines()


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


def get_opcode_addresses(w3, code) -> set:
    """
    this function returns the addresses that are references in the opcodes of a contract
    :return: address_list: list (only returning contract addresses)
    """
    opcode = disassemble_hex(code.hex())
    address_set = set()
    for op in opcode.splitlines():
        for param in op.split(' '):
            if param.startswith('0x') and len(param) == 42:
                if is_contract(w3, param):
                    address_set.add(Web3.toChecksumAddress(param))

    return address_set


def has_metadata(w3, code) -> bool:
    """
    this function determines whether the contract contains metadata
    :return: has_metadata: bool
    """

    opcode = disassemble_hex(code.hex())

    log1 = False
    push6 = False
    for op in opcode.splitlines():
        arr = op.split(' ')
        if arr[0] == 'LOG1':
            log1 = True
        if log1 and arr[0] == 'PUSH6':
            push6 = True
        if push6 and arr[0] == 'INVALID':
            return True
    return False


def get_features(w3, code) -> list:
    """
    this function returns the function hashes contained in the contract
    :return: features: list
    """
    func_hashes = set()
    opcode = disassemble_hex(code.hex())
    first_push = False
    for op in opcode.splitlines():
        arr = op.split(' ')
        if arr[0] == 'CALLDATASIZE':
            if(first_push):
                break
        if arr[0] == 'PUSH4':
            first_push = True
            func_hashes.add(arr[1])

    return func_hashes


def exec_model(code: str) -> float:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    global model

    data = pd.DataFrame(columns=features, dtype=int)
    index = len(data.index)
    data.loc[index] = np.zeros(len(features))

    func_hashes = get_features(web3, code)
    for function_hash in func_hashes:
        if function_hash in features:
            data.loc[index][function_hash] = 1
        else:
            data.loc[index]["other"] = 1 + data.loc[index]["other"]

    data.loc[index]["size"] = len(code)

    data.loc[index]["has_metadata"] = has_metadata(web3, code)

    logging.info(data[0:1])

    score = model.predict(data[0:1])
    logging.info(score)
    return score[0]


def detect_malicious_contract_creations(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    created_contract_addresses = []
    for trace in transaction_event.traces:
        if trace.type == 'create':
            if (transaction_event.from_ == trace.action.from_ or trace.action.from_ in created_contract_addresses):

                nonce = transaction_event.transaction.nonce if transaction_event.from_ == trace.action.from_ else 1  # for contracts creating other contracts, the nonce would be 1
                created_contract_address = calc_contract_address(w3, trace.action.from_, nonce)
                logging.info(f"Contract created {created_contract_address}")
                created_contract_addresses.append(created_contract_address.lower())
                return detect_malicious_contract(w3, trace.action.from_, created_contract_address)

    return []


def detect_malicious_contract(w3, from_, created_contract_address) -> list:
    findings = []

    if created_contract_address is not None:
        code = w3.eth.get_code(Web3.toChecksumAddress(created_contract_address))

        if len(code) > BYTE_CODE_LENGTH_THRESHOLD:

            # obtain all the addresses contained in the created contract and propagate to the findings
            storage_addresses = get_storage_addresses(w3, created_contract_address)
            opcode_addresses = get_opcode_addresses(w3, code)

            model_score = exec_model(code)
            if model_score > MODEL_THRESHOLD:
                findings.append(MaliciousContractFindings.malicious_contract_creation(from_, created_contract_address, set.union(storage_addresses, opcode_addresses), model_score, MODEL_THRESHOLD))

    return findings


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_malicious_contract_creations(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
