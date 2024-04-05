from hexbytes import HexBytes
import rlp
import requests
from web3 import Web3
from time import time
from concurrent.futures import ThreadPoolExecutor
import functools
import operator
from eth_abi import decode
from src.constants import CONTRACT_SLOT_ANALYSIS_DEPTH, MASK, BOT_ID,UTILITY_CONTRACT_BYTECODE,UTILITY_CONTRACT_ABI
from src.logger import logger



def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def is_contract(w3, addresses) -> list:
    # Your contract's ABI
    contract_abi = UTILITY_CONTRACT_ABI

    # The address you want to simulate the contract being deployed at
    simulated_contract_address = '0x1111111111111111111111111111111111111111'

    # The runtime bytecode of your contract
    override_code = UTILITY_CONTRACT_BYTECODE

    # Create the contract instance with the simulated address
    contract = w3.eth.contract(address=simulated_contract_address, abi=contract_abi)

    # Convert to checksum addresses
    addresses_to_check = [Web3.toChecksumAddress(addr) for addr in addresses]

    # Define the state override parameters
    state_override = {
        simulated_contract_address: {'code': override_code}
    }

    # Perform the call with state override
    call_result = w3.eth.call({
        'to': simulated_contract_address,
        'data': contract.encodeABI(fn_name='isContract', args=[addresses_to_check])
    }, 'latest', state_override)

    # Decode the result - Assuming checkEOA returns bool[]
    result = decode(['bool[]'], call_result)

    return result[0] if result else False


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
    is_contract_result = is_contract(w3, all_addresses)
    address_set = set([Web3.toChecksumAddress(all_addresses[i]) for i, contract in enumerate(is_contract_result) if contract])
    return address_set


def get_storage_addresses_with_state_override(w3, simulated_contract_address) -> set:
    """
    This function returns the addresses that are references in the storage of a contract
    (first CONTRACT_SLOT_ANALYSIS_DEPTH slots) using state override to simulate contract code.

    :param w3: Web3 instance
    :param simulated_contract_address: Address of the contract to analyze
    :param override_code: The overridden bytecode of the contract
    :return: address_set: set (only returning contract addresses)
    """

    # Specify the contract code to execute
    override_code = "0x5f5b80361460135780355481526020016001565b365ff3"

    if simulated_contract_address is None:
        return set()

    # Define the state override parameters
    state_override = {
        simulated_contract_address: {'code': override_code}
    }

    checksumed_address = Web3.toChecksumAddress(simulated_contract_address)
    all_addresses = []

    # Loop through the desired range of storage slots
    for i in range(CONTRACT_SLOT_ANALYSIS_DEPTH):
        call_result = w3.eth.call({
            'to': checksumed_address,
            'data': w3.toHex(text='')[2:] + w3.toHex(i)[2:].rjust(64, '0')
        }, 'latest', state_override)

        # Assuming call_result is the storage data, extract potential addresses
        if call_result != Web3.toBytes(hexstr='0x' + '0' * 64):
            potential_address_1 = Web3.toHex(call_result[0:20])
            potential_address_2 = Web3.toHex(call_result[12:])
            all_addresses.extend([potential_address_1, potential_address_2])

    # Deduplicate and filter out non-contract addresses
    all_addresses = list(set(all_addresses))
    is_contract_result = is_contract(w3, all_addresses)
    address_set = set([Web3.toChecksumAddress(all_addresses[i]) for i, contract in enumerate(is_contract_result) if contract])

    return address_set


def do_post(w3, payload):
    response = w3.eth_call(payload)

    # Error handling could be improved based on the needs of your application
    if 'result' in response:
        return response['result']
    elif 'error' in response:
        raise Exception(f"JSON-RPC error: {response['error']}")
    else:
        raise Exception("Malformed JSON-RPC response")


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
                is_contract_local = is_contract(w3, [opcode.operand])
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
