import forta_agent
import rlp
from forta_agent import get_json_rpc_url, EntityType
from joblib import load
from evmdasm import EvmBytecode
from web3 import Web3
from os import environ


from src.constants import (
    BYTE_CODE_LENGTH_THRESHOLD,
    MODEL_THRESHOLD,
    SAFE_CONTRACT_THRESHOLD,
)
from src.findings import TokenContractFindings
from src.logger import logger
from src.utils import (
    get_features,
    get_storage_addresses,
    is_contract,
)

from src.storage import get_secrets

SECRETS_JSON = get_secrets()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
ML_MODEL = None


def initialize():
    """
    this function loads the ml model.
    """
    global ML_MODEL
    logger.info("Start loading model")
    ML_MODEL = load("malicious_token_model_02_07_23_exp6.joblib")
    logger.info("Complete loading model")

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON["apiKeys"]["ZETTABLOCK"]


def exec_model(w3, opcodes: str, contract_creator: str) -> tuple:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    score = None
    features, opcode_addresses = get_features(w3, opcodes, contract_creator)
    score = ML_MODEL.predict_proba([features])[0][1]

    return score, opcode_addresses


def detect_malicious_token_contract_tx(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    malicious_findings = []
    safe_findings = []

    if len(transaction_event.traces) > 0:
        for trace in transaction_event.traces:
            if trace.type == "create":
                created_contract_address = (
                    trace.result.address if trace.result else None
                )
                error = trace.error if trace.error else None
                logger.info(f"Contract created {created_contract_address}")
                if error is not None:
                    if transaction_event.from_ == trace.action.from_:
                        nonce = transaction_event.transaction.nonce
                        contract_address = calc_contract_address(w3, trace.action.from_, nonce)
                    else:
                        # For contracts creating other contracts, get the nonce using Web3
                        nonce = w3.eth.getTransactionCount(Web3.toChecksumAddress(trace.action.from_), transaction_event.block_number)
                        contract_address = calc_contract_address(w3, trace.action.from_, nonce - 1)

                    logger.warn(
                        f"Contract {contract_address} creation failed with tx {trace.transactionHash}: {error}"
                    )
                # creation bytecode contains both initialization and run-time bytecode.
                creation_bytecode = trace.action.init
                for finding in detect_malicious_token_contract(
                    w3,
                    trace.action.from_,
                    created_contract_address,
                    creation_bytecode,
                ):
                    if finding.alert_id == "SUSPICIOUS-TOKEN-CONTRACT-CREATION":
                        malicious_findings.append(finding)
                    else:
                        safe_findings.append(finding)
    else:  # Trace isn't supported, To improve coverage, process contract creations from EOAs.
        if transaction_event.to is None:
            nonce = transaction_event.transaction.nonce
            created_contract_address = calc_contract_address(
                w3, transaction_event.from_, nonce
            )
            runtime_bytecode = w3.eth.get_code(
                Web3.toChecksumAddress(created_contract_address)
            ).hex()
            for finding in detect_malicious_token_contract(
                w3,
                transaction_event.from_,
                created_contract_address,
                runtime_bytecode,
            ):
                if finding.alert_id == "SUSPICIOUS-TOKEN-CONTRACT-CREATION":
                    malicious_findings.append(finding)
                else:
                    safe_findings.append(finding)

    # Reduce findings to 10 because we cannot return more than 10 findings per request
    return (malicious_findings + safe_findings)[:10]


def detect_malicious_token_contract(w3, from_, created_contract_address, code) -> list:
    findings = []

    if created_contract_address is not None:
        if len(code) > BYTE_CODE_LENGTH_THRESHOLD:
            try:
                opcodes = EvmBytecode(code).disassemble()
            except Exception as e:
                logger.warn(f"Error disassembling evm bytecode: {e}")
            # obtain all the addresses contained in the created contract and propagate to the findings
            storage_addresses = get_storage_addresses(w3, created_contract_address)
            model_score, opcode_addresses = exec_model(w3, opcodes, from_)
            from_label_type = "contract" if is_contract(w3, from_) else "eoa"
            finding = TokenContractFindings(
                from_,
                created_contract_address,
                set.union(storage_addresses, opcode_addresses),
                model_score,
                MODEL_THRESHOLD,
            )
            if model_score is not None:
                from_label_type = "contract" if is_contract(w3, from_) else "eoa"
                labels = [
                    {
                        "entity": created_contract_address,
                        "entity_type": EntityType.Address,
                        "label": "contract",
                        "confidence": 1.0,
                    },
                    {
                        "entity": from_,
                        "entity_type": EntityType.Address,
                        "label": from_label_type,
                        "confidence": 1.0,
                    },
                ]

                if model_score >= MODEL_THRESHOLD:
                    labels.extend(
                        [
                            {
                                "entity": created_contract_address,
                                "entity_type": EntityType.Address,
                                "label": "attacker",
                                "confidence": model_score,
                            },
                            {
                                "entity": from_,
                                "entity_type": EntityType.Address,
                                "label": "attacker",
                                "confidence": model_score,
                            },
                        ]
                    )

                    findings.append(
                        finding.malicious_contract_creation(
                            CHAIN_ID,
                            labels,
                        )
                    )
                elif model_score <= SAFE_CONTRACT_THRESHOLD:
                    labels.extend(
                        [
                            {
                                "entity": created_contract_address,
                                "entity_type": EntityType.Address,
                                "label": "positive_reputation",
                                "confidence": 1 - model_score,
                            },
                            {
                                "entity": from_,
                                "entity_type": EntityType.Address,
                                "label": "positive_reputation",
                                "confidence": 1 - model_score,
                            },
                        ]
                    )
                    findings.append(
                        finding.safe_contract_creation(
                            CHAIN_ID,
                            labels,
                        )
                    )
                else:
                    findings.append(finding.non_malicious_contract_creation())

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
