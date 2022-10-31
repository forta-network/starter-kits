import forta_agent
import numpy as np
import pandas as pd
import rlp
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from joblib import load
from pyevmasm import disassemble_hex
from web3 import Web3

from src.constants import (
    BYTE_CODE_LENGTH_THRESHOLD,
    CONTRACT_SLOT_ANALYSIS_DEPTH,
    MODEL_THRESHOLD,
)
from src.findings import MaliciousContractFindings
from src.logger import logger


web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
ML_MODEL = None


def initialize():
    """
    this function loads the ml model.
    """
    global ML_MODEL
    logger.info("Start loading model")
    ML_MODEL = load("model.joblib")
    logger.info("Complete loading model")


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes("0x")


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
        if mem != HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ):
            # looking at both areas of the storage slot as - depending on packing - the address could be at the beginning or the end.
            addr_on_left = mem[0:20].hex()
            addr_on_right = mem[12:].hex()
            if is_contract(w3, addr_on_left):
                address_set.add(Web3.toChecksumAddress(addr_on_left))
            if is_contract(w3, addr_on_right):
                address_set.add(Web3.toChecksumAddress(addr_on_right))

    return address_set


def get_opcode_addresses(w3, opcodes) -> set:
    """
    this function returns the addresses that are references in the opcodes of a contract
    :return: address_list: list (only returning contract addresses)
    """
    address_set = set()
    for op in opcodes.splitlines():
        for param in op.split(" "):
            if param.startswith("0x") and len(param) == 42:
                if is_contract(w3, param):
                    address_set.add(Web3.toChecksumAddress(param))

    return address_set


def get_features(opcodes) -> list:
    """
    this function returns the function hashes contained in the contract
    :return: features: list
    """
    features = []
    for op in opcodes.splitlines():
        opcode = op.split(" ")[0].strip() if op else ""
        if opcode:
            # treat unique unknown and invalid opcodes as UNKNOWN OR INVALID
            if opcode.startswith("UNKNOWN") or opcode.startswith("INVALID"):
                opcode = opcode.split("_")[0]
            features.append(opcode)

    return " ".join(features)


def exec_model(opcodes: str) -> float:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    features = get_features(opcodes)
    score = ML_MODEL.predict_proba([features])[0][1]
    logger.info(score)
    return score


def detect_malicious_contract_tx(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    all_findings = []
    created_contract_addresses = []

    if len(transaction_event.traces) > 0:
        for trace in transaction_event.traces:
            if trace.type == "create":
                if (
                    transaction_event.from_ == trace.action.from_
                    or trace.action.from_ in created_contract_addresses
                ):
                    created_contract_address = (
                        trace.result.address if trace.result else None
                    )
                    error = trace.error if trace.error else None
                    logger.info(f"Contract created {created_contract_address}")
                    if error is not None:
                        nonce = (
                            transaction_event.transaction.nonce
                            if transaction_event.from_ == trace.action.from_
                            else 1
                        )  # for contracts creating other contracts, the nonce would be 1. WARN: this doesn't handle create2 tx
                        contract_address = calc_contract_address(
                            w3, trace.action.from_, nonce
                        )
                        logger.warn(
                            f"Contract {contract_address} creation failed with tx {trace.transactionHash}: {error}"
                        )
                    created_contract_addresses.append(created_contract_address.lower())
                    all_findings.extend(
                        detect_malicious_contract(
                            w3,
                            trace.action.from_,
                            created_contract_address,
                        )
                    )
    else:  # Trace isn't supported, To improve coverage, process contract creations from EOAs.
        if transaction_event.to is None:
            nonce = transaction_event.transaction.nonce
            created_contract_address = calc_contract_address(
                w3, transaction_event.from_, nonce
            )
            all_findings.extend(
                detect_malicious_contract(
                    w3,
                    transaction_event.from_,
                    created_contract_address,
                )
            )

    return all_findings


def detect_malicious_contract(w3, from_, created_contract_address) -> list:
    findings = []

    if created_contract_address is not None:
        code = w3.eth.get_code(Web3.toChecksumAddress(created_contract_address))
        if len(code) > BYTE_CODE_LENGTH_THRESHOLD:
            opcodes = disassemble_hex(code.hex())
            # obtain all the addresses contained in the created contract and propagate to the findings
            storage_addresses = get_storage_addresses(w3, created_contract_address)
            opcode_addresses = get_opcode_addresses(w3, opcodes)

            model_score = exec_model(opcodes)
            if model_score >= MODEL_THRESHOLD:
                findings.append(
                    MaliciousContractFindings.malicious_contract_creation(
                        from_,
                        created_contract_address,
                        set.union(storage_addresses, opcode_addresses),
                        model_score,
                        MODEL_THRESHOLD,
                    )
                )

    return findings


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def provide_handle_transaction(w3):
    def handle_transaction(
        transaction_event: forta_agent.transaction_event.TransactionEvent,
    ) -> list:
        return detect_malicious_contract_tx(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
