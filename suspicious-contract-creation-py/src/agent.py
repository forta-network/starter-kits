import rlp
import asyncio
from forta_bot import get_chain_id, scan_base, scan_ethereum, run_health_check, TransactionEvent
from hexbytes import HexBytes
from pyevmasm import disassemble_hex
from web3 import AsyncWeb3
from os import environ


from constants import (CONTRACT_SLOT_ANALYSIS_DEPTH,
                           TORNADO_CASH_ADDRESSES,
                           TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE)
from findings import SuspiciousContractFindings
from storage import get_secrets


TORNADO_CASH_FUNDED_ACCOUNTS = []


async def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    print("Initializing")

    SECRETS_JSON = await get_secrets()

    global TORNADO_CASH_FUNDED_ACCOUNTS
    TORNADO_CASH_FUNDED_ACCOUNTS = []

    global CHAIN_ID
    CHAIN_ID = get_chain_id()
    print("Chain ID: ", CHAIN_ID)

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


async def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = await w3.eth.get_code(w3.to_checksum_address(address))
    return code != HexBytes('0x')


async def get_storage_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the storage of a contract (first CONTRACT_SLOT_ANALYSIS_DEPTH slots)
    :return: address_list: list (only returning contract addresses)
    """
    if address is None:
        return set()

    address_set = set()
    for i in range(CONTRACT_SLOT_ANALYSIS_DEPTH):
        mem = await w3.eth.get_storage_at(w3.to_checksum_address(address), i)
        if mem != HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000'):
            # looking at both areas of the storage slot as - depending on packing - the address could be at the beginning or the end.
            if await is_contract(w3, mem[0:20]):
                address_set.add(w3.to_checksum_address(mem[0:20].hex()))
            if await is_contract(w3, mem[12:]):
                address_set.add(w3.to_checksum_address(mem[12:].hex()))

    return address_set


async def get_opcode_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the opcodes of a contract
    :return: address_list: list (only returning contract addresses)
    """
    if address is None:
        return set()

    code = await w3.eth.get_code(w3.to_checksum_address(address))
    opcode = disassemble_hex(code.hex())
    address_set = set()
    for op in opcode.splitlines():
        for param in op.split(' '):
            if param.startswith('0x') and len(param) == 42:
                if await is_contract(w3, param):
                    address_set.add(w3.to_checksum_address(param))

    return address_set


async def detect_suspicious_contract_creations(w3, transaction_event: TransactionEvent) -> list:
    global TORNADO_CASH_FUNDED_ACCOUNTS

    findings = []

    await update_tornado_cash_funded_accounts(w3, transaction_event)

    created_contract_addresses = []
    if transaction_event.to is None:
        nonce = transaction_event.transaction.nonce
        created_contract_address = await calc_contract_address(
            w3, transaction_event.from_, nonce
        )

        storage_addresses = await get_storage_addresses(w3, created_contract_address)
        opcode_addresses = await get_opcode_addresses(w3, created_contract_address)

        created_contract_addresses.append(created_contract_address.lower())

        if w3.to_checksum_address(transaction_event.from_) in TORNADO_CASH_FUNDED_ACCOUNTS:
            # needed in case the contract creates another contract
            TORNADO_CASH_FUNDED_ACCOUNTS.append(
                w3.to_checksum_address(created_contract_address))

            findings.append(SuspiciousContractFindings.suspicious_contract_creation_tornado_cash(
                transaction_event.from_, created_contract_address, set.union(storage_addresses, opcode_addresses), CHAIN_ID, transaction_event.hash))
        else:
            findings.append(SuspiciousContractFindings.suspicious_contract_creation(
                transaction_event.from_, created_contract_address, set.union(storage_addresses, opcode_addresses), CHAIN_ID, transaction_event.hash))

    for trace in transaction_event.traces:
        if trace.type == 'create':
            if (transaction_event.from_ == trace.action.from_ or trace.action.from_ in created_contract_addresses):
                if transaction_event.from_ == trace.action.from_:
                    nonce = transaction_event.transaction.nonce
                    created_contract_address = await calc_contract_address(w3, trace.action.from_, nonce)
                else:
                    # For contracts creating other contracts, get the nonce using Web3
                    nonce = w3.eth.getTransactionCount(w3.to_checksum_address(trace.action.from_), transaction_event.block_number)
                    created_contract_address = await calc_contract_address(w3, trace.action.from_, nonce - 1)

                # obtain all the addresses contained in the created contract and propagate to the findings
                storage_addresses = await get_storage_addresses(
                    w3, created_contract_address)
                opcode_addresses = await get_opcode_addresses(
                    w3, created_contract_address)

                created_contract_addresses.append(
                    created_contract_address.lower())

                if w3.to_checksum_address(trace.action.from_) in TORNADO_CASH_FUNDED_ACCOUNTS:
                    # needed in case the contract creates another contract
                    TORNADO_CASH_FUNDED_ACCOUNTS.append(
                        w3.to_checksum_address(created_contract_address))

                    findings.append(SuspiciousContractFindings.suspicious_contract_creation_tornado_cash(
                        trace.action.from_, created_contract_address, set.union(storage_addresses, opcode_addresses), CHAIN_ID, transaction_event.hash))
                else:
                    findings.append(SuspiciousContractFindings.suspicious_contract_creation(
                        trace.action.from_, created_contract_address, set.union(storage_addresses, opcode_addresses), CHAIN_ID, transaction_event.hash))

    return findings


async def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return w3.to_checksum_address(w3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


async def update_tornado_cash_funded_accounts(w3, transaction_event: TransactionEvent):
    """
    this function maintains a list of tornado cash funded accounts; holds up to TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE in memory
    :return: None
    """

    global TORNADO_CASH_FUNDED_ACCOUNTS

    for trace in transaction_event.traces:
        if trace.action.value is not None and trace.action.value > 0 and w3.to_checksum_address(trace.action.from_) in TORNADO_CASH_ADDRESSES:
            TORNADO_CASH_FUNDED_ACCOUNTS.append(
                w3.to_checksum_address(trace.action.to))
            if len(TORNADO_CASH_FUNDED_ACCOUNTS) > TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE:
                TORNADO_CASH_FUNDED_ACCOUNTS.pop(0)


async def handle_transaction(transaction_event: TransactionEvent, web3: AsyncWeb3.AsyncHTTPProvider) -> list:
    return await detect_suspicious_contract_creations(web3, transaction_event)

async def main():
    await initialize()

    await asyncio.gather(
        scan_ethereum({
        'rpc_url': "https://eth-mainnet.g.alchemy.com/v2",
        'rpc_key_id': "ebbd1b21-4e72-4d80-b4f9-f605fee5eb68",
        'local_rpc_url': "1",
        'handle_transaction': handle_transaction
        }),

        run_health_check()
    )


if __name__ == "__main__":
    asyncio.run(main())
