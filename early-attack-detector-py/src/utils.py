from hexbytes import HexBytes
import rlp
from web3 import AsyncWeb3
from time import time
from concurrent.futures import ThreadPoolExecutor
import functools
import operator
import aiohttp
import asyncio

from constants import CONTRACT_SLOT_ANALYSIS_DEPTH, MASK, BOT_ID
from logger import logger


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return w3.to_checksum_address(w3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


async def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = await w3.eth.get_code(w3.to_checksum_address(address))
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


async def get_storage_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the storage of a contract (first CONTRACT_SLOT_ANALYSIS_DEPTH slots)
    :return: address_list: list (only returning contract addresses)
    """
    if address is None:
        return set()

    checksumed_address = w3.to_checksum_address(address)
    tasks = [w3.eth.get_storage_at(checksumed_address, i) for i in range(CONTRACT_SLOT_ANALYSIS_DEPTH)]
    futures_result = await asyncio.gather(*tasks)

    all_addresses = [
        [result[0:20].hex(), result[12:].hex()]
        for result in futures_result
        if result != HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000')
    ]
    all_addresses_flat = set(functools.reduce(operator.iconcat, all_addresses, []))

    contract_checks = [is_contract(w3, addr) for addr in all_addresses_flat]
    contract_results = await asyncio.gather(*contract_checks)

    address_set = {w3.to_checksum_address(addr) for addr, is_contract in zip(all_addresses_flat, contract_results) if is_contract}
    return address_set


async def get_features(w3, opcodes, contract_creator) -> list:
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
                is_contract_local = await is_contract(w3, opcode.operand)
                checked_contracts[opcode.operand] = is_contract_local
            if is_contract_local:
                opcode_addresses.add(w3.to_checksum_address(f"0x{opcode.operand}"))

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


async def alert_count(chain_id: int, alert_id: str) -> int:
    alert_stats_url = f"https://api.forta.network/stats/bot/{BOT_ID}/alerts?chainId={chain_id}"
    alert_id_counts = 1
    alert_counts = 1
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(alert_stats_url) as response:
                result = await response.json()
                alert_id_counts = result["alertIds"][alert_id]["count"]
                alert_counts = result["total"]["count"]
    except Exception as err:
        logger.error(f"Error obtaining alert counts: {err}")

    return alert_id_counts, alert_counts
