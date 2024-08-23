from hexbytes import HexBytes
import rlp
import requests
from web3 import Web3
from time import time
from concurrent.futures import ThreadPoolExecutor
import functools
import operator
import pandas as pd
import logging
import io
import re

from src.constants import CONTRACT_SLOT_ANALYSIS_DEPTH, MASK, BOT_ID
from src.logger import logger


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
    return code != HexBytes("0x")

def get_function_signatures(w3, opcodes) -> set:
    """
    this function will parse the opcodes and returns all the possible function signatures (essentially whenever we find a 4bytes in a PUSH4 instruction (e.g. PUSH4 0x42966c68))
    """
    function_signatures = set()
    for i, opcode in enumerate(opcodes):
        opcode_name = opcode.name
        if opcode_name == "PUSH4" or opcode_name == "PUSH3":
            function_signatures.add(f"0x{opcode.operand}")
    return function_signatures


def get_storage_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the storage of a contract (first CONTRACT_SLOT_ANALYSIS_DEPTH slots)
    :return: address_list: list (only returning contract addresses)
    """
    if address is None:
        return set()
    
    tp_executor = ThreadPoolExecutor(max_workers=10)
    checksumed_address = Web3.toChecksumAddress(address)
    futures = [tp_executor.submit(w3.eth.get_storage_at, checksumed_address, i) for i in range(CONTRACT_SLOT_ANALYSIS_DEPTH)]
    tp_executor.shutdown(wait=True)
    futures_result = [f.result() for f in futures]
    all_addresses = [[result[0:20].hex(), result[12:].hex()] for result in futures_result if result != HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000')]
    all_addresses = list(set(functools.reduce(operator.iconcat, all_addresses, [])))
    tp_executor = ThreadPoolExecutor(max_workers=10)
    futures = [tp_executor.submit(is_contract, w3, address) for address in all_addresses]
    tp_executor.shutdown(wait=True)
    address_set = set([Web3.toChecksumAddress(all_addresses[i]) for i, f in enumerate(futures) if f.result()])
    return address_set


def get_features(w3, opcodes, contract_creator) -> list:
    """
    this function returns the contract opcodes
    :return: features: list
    """
    features = []
    opcode_addresses = set()
    checked_contracts = {}
    for i, opcode in enumerate(opcodes):
        opcode_name = opcode.name
        # treat unique unknown and invalid opcodes as UNKNOWN OR INVALID
        if opcode_name.startswith("UNKNOWN") or opcode_name.startswith("INVALID"):
            opcode_name = opcode.name.split("_")[0]
        features.append(opcode_name)
        if len(opcode.operand) == 40:
            if opcode.operand is not None and opcode.operand in checked_contracts.keys():
                is_contract_local = checked_contracts[opcode.operand]
            else:
                is_contract_local = is_contract(w3, opcode.operand)
                checked_contracts[opcode.operand] = is_contract_local
            if is_contract_local:
                opcode_addresses.add(Web3.toChecksumAddress(f"0x{opcode.operand}"))

        if opcode_name in {"PUSH4", "PUSH32"}:
            features.append(opcode.operand)
        elif opcode_name == "PUSH20":
            if opcode.operand == contract_creator:
                features.append("creator")
            elif opcode.operand == MASK:
                features.append(MASK)
            else:
                features.append("addr")

    features = " ".join(features)

    return features, opcode_addresses


def alert_count(chain_id: int, alert_id: str) -> int:
    alert_stats_url = (
        f"https://api.forta.network/stats/bot/{BOT_ID}/alerts?chainId={chain_id}"
    )
    alert_id_counts = 1
    alert_counts = 1
    try:
        result = requests.get(alert_stats_url).json()
        alert_id_counts = result["alertIds"][alert_id]["count"]
        alert_counts = result["total"]["count"]
    except Exception as err:
        logger.error(f"Error obtaining alert counts: {err}")

    return alert_id_counts, alert_counts

def get_tp_attacker_list() -> list:
    res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/main/early-attack-detector-py/tp_list.csv')
    if res.status_code == 200:
        logging.info(f"Successfully made request to fetch tp list: {res.status_code}.")
        content = res.content.decode('utf-8')
    else:
        logging.info(f"Made request to fetch tp list and failed. status code: {res.status_code}. Fetching from 'tp_list.csv'.")
        content = open('tp_list.csv', 'r').read()

    df_fps = pd.read_csv(io.StringIO(content), sep=',')
    attacker_list = set(df_fps['Attacker'].tolist())

    eth_address_pattern = re.compile(r'^0x[a-fA-F0-9]{40}$')

    unique_attacker_addresses = set()
    # Could be populated by random strings
    # and non-Ethereum addresses
    non_eth_entries = []

    for entry in attacker_list:
        # some values were sneaking in as `float` types
        # (e.g. 'nan')
        if isinstance(entry, str):
            parts = [part.strip() for part in entry.split(',')]
            for part in parts:
                if eth_address_pattern.match(part):
                    unique_attacker_addresses.add(part.lower())
                else:
                    non_eth_entries.append(part.lower())
            
    return list(unique_attacker_addresses)

def update_tp_attacker_list(current_tp_list) -> list:
    fetched_tp_list = get_tp_attacker_list()

    for entry in fetched_tp_list:
        if entry not in current_tp_list:
            current_tp_list.append(entry)

    return current_tp_list