import logging
import sys
import threading
from datetime import datetime, timedelta
from os import environ
import concurrent.futures
from functools import lru_cache

import forta_agent
import rlp
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from pyevmasm import disassemble_hex
from web3 import Web3
import time

from src.blockexplorer import BlockExplorer
from src.constants import CONTRACT_SLOT_ANALYSIS_DEPTH, WAIT_TIME, CONCURRENT_SIZE
from src.findings import UnverifiedCodeContractFindings
from src.storage import get_secrets

SECRETS_JSON = get_secrets()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
blockexplorer = BlockExplorer(web3.eth.chain_id)

FINDINGS_CACHE = []
MUTEX = False
THREAD_STARTED = False
CREATED_CONTRACTS = {}  # contract and creation timestamp


root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global FINDINGS_CACHE
    FINDINGS_CACHE = []

    global MUTEX
    MUTEX = False

    global THREAD_STARTED
    THREAD_STARTED = False

    global CREATED_CONTRACTS
    CREATED_CONTRACTS = {}

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON["apiKeys"]["ZETTABLOCK"]


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


@lru_cache(maxsize=12800)
def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    try:
        code = w3.eth.get_code(Web3.toChecksumAddress(address))
        return code != HexBytes("0x")
    except Exception as e:
        logging.warn(f"Web3 error for is_contract method", {address: address, e: e})
        return False


def get_storage_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the storage of a contract (first CONTRACT_SLOT_ANALYSIS_DEPTH slots)
    :return: address_list: list (only returning contract addresses)
    """
    start_time = time.time()

    if address is None:
        return set()

    address_set = set()

    def get_storage_at_slot(size):
        for i in size:
            try:
                mem = w3.eth.get_storage_at(Web3.toChecksumAddress(address), i)
                if mem != HexBytes(
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                ):
                    # looking at both areas of the storage slot as - depending on packing - the address could be at the beginning or the end.
                    if is_contract(w3, mem[0:20]):
                        address_set.add(Web3.toChecksumAddress(mem[0:20].hex()))
                    if is_contract(w3, mem[12:]):
                        address_set.add(Web3.toChecksumAddress(mem[12:].hex()))
            except Exception as e:
                logging.warning(
                    f"Web3 Error at get_storage_at method", {address: address, e: e}
                )

    concurrent_sizes = [
        range(i, min(i + CONCURRENT_SIZE, CONTRACT_SLOT_ANALYSIS_DEPTH))
        for i in range(0, CONTRACT_SLOT_ANALYSIS_DEPTH, CONCURRENT_SIZE)
    ]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(get_storage_at_slot, concurrent_sizes)

    end_time = time.time()

    logging.info(f"get_storage_addresses took {end_time - start_time} seconds")

    return address_set


def get_opcode_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the opcodes of a contract
    :return: address_list: list (only returning contract addresses)
    """
    start_time = time.time()

    if address is None:
        return set()

    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    opcode = disassemble_hex(code.hex())

    address_set = set()
    for op in opcode.splitlines():
        for param in op.split(" "):
            if param.startswith("0x") and len(param) == 42:
                if is_contract(w3, param):
                    address_set.add(Web3.toChecksumAddress(param))

    end_time = time.time()

    logging.info(f"get_opcode_addresses took {end_time - start_time} seconds")

    return address_set


def cache_contract_creation(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
):
    global CREATED_CONTRACTS
    global MUTEX

    logging.info(
        f"Scanning transaction {transaction_event.transaction.hash} on chain {w3.eth.chain_id}"
    )
    while MUTEX:
        logging.info(f"Sleeping...")
        time.sleep(1)  # 1 sec

    MUTEX = True
    created_contract_addresses = []
    if transaction_event.to is None:
        nonce = transaction_event.transaction.nonce
        created_contract_address = calc_contract_address(
            w3, transaction_event.from_, nonce
        )

        logging.info(
            f"Added contract {created_contract_address} to cache. Timestamp: {transaction_event.timestamp}"
        )
        CREATED_CONTRACTS[created_contract_address] = transaction_event

    for trace in transaction_event.traces:
        if trace.type == "create":
            if (
                transaction_event.from_ == trace.action.from_
                or trace.action.from_ in created_contract_addresses
            ):
                # for contracts creating other contracts, the nonce would be 1
                nonce = (
                    transaction_event.transaction.nonce
                    if transaction_event.from_ == trace.action.from_
                    else 1
                )
                created_contract_address = calc_contract_address(
                    w3, trace.action.from_, nonce
                )
                logging.info(
                    f"Added contract {created_contract_address} to cache. Timestamp: {transaction_event.timestamp}"
                )

                CREATED_CONTRACTS[created_contract_address] = transaction_event
    MUTEX = False
    contracts_count = len(CREATED_CONTRACTS.items())
    logging.info(f"Created Contracts Count = {contracts_count}")


def detect_unverified_contract_creation(
    w3, blockexplorer, wait_time=WAIT_TIME, infinite=True
):
    global CREATED_CONTRACTS
    global FINDINGS_CACHE
    global MUTEX

    try:
        while True:
            if not MUTEX:
                MUTEX = True
                # logging.info(f"In detect_unverified MUtex was set to: {MUTEX}")
                for (
                    created_contract_address,
                    transaction_event,
                ) in CREATED_CONTRACTS.items():
                    logging.info(
                        f"Evaluating contract {created_contract_address} from cache."
                    )
                    created_contract_addresses = []
                    if transaction_event.to is None:
                        logging.info(
                            f"Contract {created_contract_address} created by EOA."
                        )
                        nonce = transaction_event.transaction.nonce
                        created_contract_address = calc_contract_address(
                            w3, transaction_event.from_, nonce
                        )
                        if (
                            datetime.now()
                            - datetime.fromtimestamp(transaction_event.timestamp)
                        ) > timedelta(minutes=wait_time):
                            logging.info(
                                f"Evaluating contract {created_contract_address} from cache. Is old enough."
                            )
                            if not blockexplorer.is_verified(created_contract_address):
                                logging.info(
                                    f"Identified unverified contract: {created_contract_address}"
                                )

                                storage_addresses = get_storage_addresses(
                                    w3, created_contract_address
                                )

                                opcode_addresses = get_opcode_addresses(
                                    w3, created_contract_address
                                )

                                created_contract_addresses.append(
                                    created_contract_address.lower()
                                )

                                FINDINGS_CACHE.append(
                                    UnverifiedCodeContractFindings.unverified_code(
                                        transaction_event.from_,
                                        created_contract_address,
                                        CHAIN_ID,
                                        set.union(storage_addresses, opcode_addresses),
                                    )
                                )

                                CREATED_CONTRACTS.pop(created_contract_address)
                            else:
                                logging.info(
                                    f"Identified verified contract: {created_contract_address}"
                                )

                    for trace in transaction_event.traces:
                        if trace.type == "create":
                            logging.info(
                                f"Contract {created_contract_address} created within trace."
                            )

                            if (
                                transaction_event.from_ == trace.action.from_
                                or trace.action.from_ in created_contract_addresses
                            ):
                                # for contracts creating other contracts, the nonce would be 1
                                nonce = (
                                    transaction_event.transaction.nonce
                                    if transaction_event.from_ == trace.action.from_
                                    else 1
                                )
                                calc_created_contract_address = calc_contract_address(
                                    w3, trace.action.from_, nonce
                                )
                                if (
                                    created_contract_address
                                    == calc_created_contract_address
                                ):
                                    if (
                                        datetime.now()
                                        - datetime.fromtimestamp(
                                            transaction_event.timestamp
                                        )
                                    ) > timedelta(minutes=wait_time):
                                        logging.info(
                                            f"Evaluating contract {created_contract_address} from cache. Is old enough."
                                        )
                                        if not blockexplorer.is_verified(
                                            created_contract_address
                                        ):
                                            logging.info(
                                                f"Identified unverified contract: {created_contract_address}"
                                            )
                                            storage_addresses = get_storage_addresses(
                                                w3, created_contract_address
                                            )

                                            opcode_addresses = get_opcode_addresses(
                                                w3, created_contract_address
                                            )

                                            created_contract_addresses.append(
                                                created_contract_address.lower()
                                            )

                                            FINDINGS_CACHE.append(
                                                UnverifiedCodeContractFindings.unverified_code(
                                                    trace.action.from_,
                                                    created_contract_address,
                                                    CHAIN_ID,
                                                    set.union(
                                                        storage_addresses,
                                                        opcode_addresses,
                                                    ),
                                                )
                                            )
                                            CREATED_CONTRACTS.pop(
                                                created_contract_address
                                            )
                                        else:
                                            logging.info(
                                                f"Identified verified contract: {created_contract_address}"
                                            )
                if not infinite:
                    break
                MUTEX = False

    except Exception as e:
        logging.warning(f"Exception: {e}")
        MUTEX = False


def provide_handle_transaction(w3, blockexplorer):
    def handle_transaction(
        transaction_event: forta_agent.transaction_event.TransactionEvent,
    ) -> list:
        global FINDINGS_CACHE
        global THREAD_STARTED

        if not THREAD_STARTED:
            THREAD_STARTED = True
            thread = threading.Thread(
                target=detect_unverified_contract_creation, args=(w3, blockexplorer)
            )
            thread.start()

        cache_contract_creation(w3, transaction_event)
        # uncomment for local testing; otherwise the process will exit
        while thread.is_alive():
            pass

        findings = FINDINGS_CACHE
        FINDINGS_CACHE = []
        return findings

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3, blockexplorer)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
