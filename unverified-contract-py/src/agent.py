import asyncio
import logging
import sys
import threading
from datetime import datetime, timedelta
from os import environ
from async_lru import alru_cache

from forta_bot_sdk import scan_ethereum, scan_fantom, scan_avalanche, scan_base, scan_bsc, scan_optimism, scan_polygon, scan_arbitrum, TransactionEvent, get_chain_id, run_health_check
from web3 import AsyncWeb3
import rlp
from hexbytes import HexBytes
from pyevmasm import disassemble_hex
import time

from blockexplorer import BlockExplorer
from constants import CONTRACT_SLOT_ANALYSIS_DEPTH, WAIT_TIME, CONCURRENT_SIZE
from findings import UnverifiedCodeContractFindings

SECRETS_JSON = None

blockexplorer = BlockExplorer(get_chain_id())

FINDINGS_CACHE = []
THREAD_STARTED = False
CREATED_CONTRACTS = {}  # contract and creation timestamp
LOCK = threading.Lock()

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)


async def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global FINDINGS_CACHE
    FINDINGS_CACHE = []

    global THREAD_STARTED
    THREAD_STARTED = False

    global CREATED_CONTRACTS
    CREATED_CONTRACTS = {}

    global CHAIN_ID
    CHAIN_ID = get_chain_id()

    await blockexplorer.set_api_key()

    global SECRETS_JSON
    SECRETS_JSON = blockexplorer.get_secrets()

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON["apiKeys"]["ZETTABLOCK"]


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return w3.to_checksum_address(w3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


@alru_cache(maxsize=12800)
async def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    try:
        code = await w3.eth.get_code(w3.to_checksum_address(address))
        return code != HexBytes("0x")
    except Exception as e:
        logging.warn(f"Web3 error for is_contract method", {address: address, e: e})
        return False

@alru_cache(maxsize=12800)
async def get_storage_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the storage of a contract (first CONTRACT_SLOT_ANALYSIS_DEPTH slots)
    :return: address_list: list (only returning contract addresses)
    """
    start_time = time.time()

    if address is None:
        return set()

    address_set = set()

    async def get_storage_at_slot(size):
        for i in size:
            try:
                mem = await w3.eth.get_storage_at(w3.to_checksum_address(address), i)
                if mem != HexBytes(
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                ):
                    # looking at both areas of the storage slot as - depending on packing - the address could be at the beginning or the end.
                    is_contract_first_half_contract = await is_contract(w3, mem[0:20])
                    is_contract_second_half_contract = await is_contract(w3, mem[12:])

                    if is_contract_first_half_contract:
                        address_set.add(w3.to_checksum_address(mem[0:20].hex()))
                    if is_contract_second_half_contract:
                        address_set.add(w3.to_checksum_address(mem[12:].hex()))
            except Exception as e:
                logging.warning(
                    f"Web3 Error at get_storage_at method", {address: address, e: e}
                )

    concurrent_sizes = [
        range(i, min(i + CONCURRENT_SIZE, CONTRACT_SLOT_ANALYSIS_DEPTH))
        for i in range(0, CONTRACT_SLOT_ANALYSIS_DEPTH, CONCURRENT_SIZE)
    ]

    tasks = [get_storage_at_slot(size) for size in concurrent_sizes]
    await asyncio.gather(*tasks)

    end_time = time.time()

    logging.info(f"get_storage_addresses took {end_time - start_time} seconds")

    return address_set


@alru_cache(maxsize=12800)
async def get_opcode_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the opcodes of a contract
    :return: address_list: list (only returning contract addresses)
    """
    start_time = time.time()

    if address is None:
        return set()

    code = await w3.eth.get_code(w3.to_checksum_address(address))
    opcode = disassemble_hex(code.hex())

    address_set = set()
    for op in opcode.splitlines():
        for param in op.split(" "):
            if param.startswith("0x") and len(param) == 42:
                if await is_contract(w3, param):
                    address_set.add(w3.to_checksum_address(param))

    end_time = time.time()

    logging.info(f"get_opcode_addresses took {end_time - start_time} seconds")

    return address_set


def cache_contract_creation(
    w3, transaction_event: TransactionEvent
):
    global CREATED_CONTRACTS


    logging.info(
        f"Scanning transaction {transaction_event.transaction.hash} on chain {CHAIN_ID}"
    )

    with LOCK:
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
                    if transaction_event.from_ == trace.action.from_:
                        nonce = transaction_event.transaction.nonce
                        created_contract_address = calc_contract_address(w3, trace.action.from_, nonce)
                    else:
                        # For contracts creating other contracts, get the nonce using Web3
                        nonce = w3.eth.getTransactionCount(w3.to_checksum_address(trace.action.from_), transaction_event.block_number)
                        created_contract_address = calc_contract_address(w3, trace.action.from_, nonce - 1)

                    if created_contract_address not in CREATED_CONTRACTS:
                        logging.info(
                            f"Added contract {created_contract_address} to cache. Timestamp: {transaction_event.timestamp}"
                        )

                        CREATED_CONTRACTS[created_contract_address] = transaction_event

    contracts_count = len(CREATED_CONTRACTS.items())
    logging.info(f"Created Contracts Count = {contracts_count}")


async def detect_unverified_contract_creation(
    w3, blockexplorer, wait_time=WAIT_TIME, infinite=True
):
    global CREATED_CONTRACTS
    global FINDINGS_CACHE

    try:
        while True:
            with LOCK:
                for (
                    created_contract_address,
                    transaction_event,
                ) in CREATED_CONTRACTS.copy().items():
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
                            is_contract_verified = await blockexplorer.is_verified(created_contract_address)
                            if not is_contract_verified:
                                logging.info(
                                    f"Identified unverified contract: {created_contract_address}"
                                )

                                storage_addresses = await get_storage_addresses(
                                    w3, created_contract_address
                                )

                                opcode_addresses = await get_opcode_addresses(
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
                                        transaction_event.hash
                                    )
                                )

                                CREATED_CONTRACTS.pop(created_contract_address)
                            else:
                                logging.info(
                                    f"Identified verified contract: {created_contract_address}"
                                )
                                CREATED_CONTRACTS.pop(created_contract_address, None)

                    for trace in transaction_event.traces:
                        if trace.type == "create":
                            logging.info(
                                f"Contract {created_contract_address} created within trace."
                            )

                            if (
                                transaction_event.from_ == trace.action.from_
                                or trace.action.from_ in created_contract_addresses
                            ):
                                if transaction_event.from_ == trace.action.from_:
                                    nonce = transaction_event.transaction.nonce
                                    calc_created_contract_address = calc_contract_address(w3, trace.action.from_, nonce)
                                else:
                                    # For contracts creating other contracts, get the nonce using Web3
                                    nonce = w3.eth.getTransactionCount(w3.to_checksum_address(trace.action.from_), transaction_event.block_number)
                                    calc_created_contract_address = calc_contract_address(w3, trace.action.from_, nonce - 1)

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
                                        is_verified = await blockexplorer.is_verified(created_contract_address)
                                        if not is_verified:
                                            logging.info(
                                                f"Identified unverified contract: {created_contract_address}"
                                            )
                                            storage_addresses = await get_storage_addresses(
                                                w3, created_contract_address
                                            )

                                            opcode_addresses = await get_opcode_addresses(
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
                                                    trace.transaction_hash
                                                )
                                            )
                                            CREATED_CONTRACTS.pop(
                                                created_contract_address, None
                                            )
                                        else:
                                            logging.info(
                                                f"Identified verified contract: {created_contract_address}"
                                            )
                                            CREATED_CONTRACTS.pop(created_contract_address, None)
            if not infinite:
                break

    except Exception as e:
        logging.warning(f"Exception: {e}")


async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider):
    async def provide_handle_transaction(
        w3,
        blockexplorer,
        transaction_event
    ) -> list:
        global FINDINGS_CACHE
        global THREAD_STARTED

        if not THREAD_STARTED:
            THREAD_STARTED = True
            thread = threading.Thread(
                target=lambda: asyncio.run(detect_unverified_contract_creation(w3, blockexplorer))
            )
            thread.start()

        cache_contract_creation(w3, transaction_event)
        # uncomment for local testing; otherwise the process will exit
        # while thread.is_alive():
        #     pass

        findings = FINDINGS_CACHE
        FINDINGS_CACHE = []
        return findings

    return await provide_handle_transaction(web3, blockexplorer, transaction_event)


async def main():
    await initialize()

    await asyncio.gather(
        scan_ethereum({
            'rpc_url': "https://rpc.ankr.com/eth",
            # 'rpc_key_id': "c795687c-5795-4d63-bcb1-f18b5a391dc4",
            'local_rpc_url': "1",
            'handle_transaction': handle_transaction
        }),
        scan_optimism({
            'rpc_url': "https://rpc.ankr.com/optimism",
            # 'rpc_key_id': "be4bb945-3e18-4045-a7c4-c3fec8dbc3e1",
            'local_rpc_url': "10",
            'handle_transaction': handle_transaction
        }),
        scan_polygon({
            'rpc_url': "https://rpc.ankr.com/polygon",
            # 'rpc_key_id': "889fa483-ddd8-4fc0-b6d9-baa1a1a65119",
            'local_rpc_url': "137",
            'handle_transaction': handle_transaction
        }),
        scan_base({
            'rpc_url': "https://rpc.ankr.com/base",
            # 'rpc_key_id': "166a510e-edca-4c3d-86e2-7cc49cd90f7f",
            'local_rpc_url': "8453",
            'handle_transaction': handle_transaction
        }),
        scan_arbitrum({
            'rpc_url': "https://rpc.ankr.com/arbitrum",
            # 'rpc_key_id': "09037aa1-1e48-4092-ad3b-cf22c89d5b8a",
            'local_rpc_url': "42161",
            'handle_transaction': handle_transaction
        }),
        scan_avalanche({
            'rpc_url': "https://rpc.ankr.com/avalanche",
            # 'rpc_key_id': "09037aa1-1e48-4092-ad3b-cf22c89d5b8a",
            'local_rpc_url': "43114",
            'handle_transaction': handle_transaction
        }),
        scan_fantom({
            'rpc_url': "https://rpc.ankr.com/fantom",
            # 'rpc_key_id': "09037aa1-1e48-4092-ad3b-cf22c89d5b8a",
            'local_rpc_url': "250",
            'handle_transaction': handle_transaction
        }),
        scan_bsc({
            'rpc_url': "https://rpc.ankr.com/bsc",
            'local_rpc_url': "56",
            'handle_transaction': handle_transaction
        }),
        run_health_check()
    )

if __name__ == "__main__":
    asyncio.run(main())
