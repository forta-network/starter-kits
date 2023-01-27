from datetime import datetime
import forta_agent
import numpy as np
import pandas as pd
import rlp
from forta_agent import get_json_rpc_url, EntityType
from joblib import load
from pyevmasm import disassemble_hex
from web3 import Web3

from src.constants import (
    BYTE_CODE_LENGTH_THRESHOLD,
    MODEL_THRESHOLD,
)
from src.findings import MaliciousContractFindings
from src.logger import logger
from src.utils import (
    get_features,
    get_storage_addresses,
    get_opcode_addresses,
    get_anomaly_score,
    is_contract,
    update_contract_deployment_counter,
)


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
                date_time = datetime.now()
                date_hour = date_time.strftime("%d/%m/%Y %H:00:00")
                update_contract_deployment_counter(date_hour)
                all_findings.extend(
                    detect_malicious_contract(
                        w3,
                        trace.action.from_,
                        created_contract_address,
                    )
                )
    else:  # Trace isn't supported, To improve coverage, process contract creations from EOAs.
        if transaction_event.to is None:
            date_time = datetime.now()
            date_hour = date_time.strftime("%d/%m/%Y %H:00:00")
            update_contract_deployment_counter(date_hour)
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
            anomaly_score = get_anomaly_score(w3.eth.chain_id)

            model_score = exec_model(opcodes)
            from_label_type = "contract" if is_contract(w3, from_) else "eoa"
            if model_score >= MODEL_THRESHOLD:
                labels = [
                    {
                        "entity": created_contract_address,
                        "entity_type": EntityType.Address,
                        "label": "malicious",
                        "confidence": model_score,
                    },
                    {
                        "entity": created_contract_address,
                        "entity_type": EntityType.Address,
                        "label": "contract",
                        "confidence": 1.0,
                    },
                    {
                        "entity": from_,
                        "entity_type": EntityType.Address,
                        "label": "malicious",
                        "confidence": model_score,
                    },
                    {
                        "entity": from_,
                        "entity_type": EntityType.Address,
                        "label": from_label_type,
                        "confidence": 1.0,
                    },
                ]

                findings.append(
                    MaliciousContractFindings.malicious_contract_creation(
                        from_,
                        created_contract_address,
                        set.union(storage_addresses, opcode_addresses),
                        model_score,
                        MODEL_THRESHOLD,
                        anomaly_score,
                        labels,
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
