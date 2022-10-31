import forta_agent
from fsspec import get_fs_token_paths
import numpy as np
import pandas as pd
import rlp
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from joblib import load
from evmdasm import EvmBytecode
from web3 import Web3

from src.constants import (
    BYTE_CODE_LENGTH_THRESHOLD,
    CONTRACT_SLOT_ANALYSIS_DEPTH,
    MODEL_THRESHOLD,
    TOKEN_TYPES,
    ERC721_SIGHASHES,
    ERC20_SIGHASHES,
    ERC1155_SIGHASHES,
    ERC777_SIGHASHES,
)
from src.findings import MaliciousTokenContractFindings
from src.logger import logger


web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
ML_MODEL = None


def initialize():
    """
    this function loads the ml model.
    """
    global ML_MODEL
    logger.info("Start loading model")
    ML_MODEL = load("malicious_token_model_sighashes_10_29_22.joblib")
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


def get_contract_type(opcodes: str, function_sighashes: set) -> str:
    """
    this function determines contract type based on available sighashes.
    :return: contract_type: str
    """
    if function_sighashes.intersection(ERC777_SIGHASHES):
        return "erc777"
    elif function_sighashes.intersection(ERC1155_SIGHASHES):
        return "erc1155"
    elif function_sighashes.intersection(ERC721_SIGHASHES):
        return "erc721"
    elif function_sighashes.intersection(ERC20_SIGHASHES):
        return "erc20"
    elif "DELEGATECALL" in opcodes:
        return "proxy"
    else:
        return "non-token-or-proxy"


def get_features(w3, opcodes) -> list:
    """
    this function returns the opcodes + function hashes contained in the contract
    :return: features: list
    """
    features = []
    function_sighashes = set()
    opcode_addresses = set()

    for i, opcode in enumerate(opcodes):
        opcode_name = opcode.name
        # treat unique unknown and invalid opcodes as UNKNOWN OR INVALID
        if opcode_name.startswith("UNKNOWN") or opcode_name.startswith("INVALID"):
            opcode_name = opcode.name.split("_")[0]
        features.append(opcode_name)
        if len(opcode.operand) == 40 and is_contract(w3, opcode.operand):
            opcode_addresses.add(Web3.toChecksumAddress(f"0x{opcode.operand}"))

        if i < (len(opcodes) - 3):
            if (
                opcodes[i].name == "PUSH4"
                and opcodes[i + 1].name == "EQ"
                and opcodes[i + 2].name == "PUSH2"
                and opcodes[i + 3].name == "JUMPI"
            ):  # add function sighashes
                features.append(opcode.operand)
                function_sighashes.add(opcode.operand)
    features = " ".join(features)
    contract_type = get_contract_type(features, function_sighashes)

    return features, opcode_addresses, contract_type


def exec_model(w3, opcodes: str) -> tuple:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    score = None
    features, opcode_addresses, contract_type = get_features(w3, opcodes)
    if contract_type in TOKEN_TYPES:
        score = ML_MODEL.predict_proba([features])[0][1]
    logger.info(f"{contract_type}: {score}")

    return score, opcode_addresses, contract_type


def detect_malicious_token_contract_tx(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    all_findings = []

    if len(transaction_event.traces) > 0:
        for trace in transaction_event.traces:
            if trace.type == "create":
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
                all_findings.extend(
                    detect_malicious_token_contract(
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
                detect_malicious_token_contract(
                    w3,
                    transaction_event.from_,
                    created_contract_address,
                )
            )

    return all_findings


def detect_malicious_token_contract(w3, from_, created_contract_address) -> list:
    findings = []

    if created_contract_address is not None:
        code = w3.eth.get_code(Web3.toChecksumAddress(created_contract_address))
        if len(code) > BYTE_CODE_LENGTH_THRESHOLD:
            try:
                opcodes = EvmBytecode(code.hex()).disassemble()
            except Exception as e:
                logger.warn(f"Error disassembling evm bytecode: {e}")
            # obtain all the addresses contained in the created contract and propagate to the findings
            storage_addresses = get_storage_addresses(w3, created_contract_address)
            model_score, opcode_addresses, contract_type = exec_model(w3, opcodes)
            if model_score is not None and model_score >= MODEL_THRESHOLD:
                findings.append(
                    MaliciousTokenContractFindings.malicious_contract_creation(
                        from_,
                        contract_type,
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
        return detect_malicious_token_contract_tx(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
