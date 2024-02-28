import forta_agent
from forta_agent import get_json_rpc_url, EntityType, FindingSeverity
from joblib import load
from evmdasm import EvmBytecode
from web3 import Web3
from os import environ
import time
import os

from src.constants import (
    BYTE_CODE_LENGTH_THRESHOLD,
    MODEL_THRESHOLD_ETH,
    MODEL_THRESHOLD_DEFAULT,
    MODEL_THRESHOLD_ETH_PRECISION,
    FUNDING_BOTS,
)
from src.findings import ContractFindings
from src.logger import logger
from src.utils import (
    calc_contract_address,
    get_features,
    get_function_signatures,
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

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    global ML_MODEL
    logger.info("Start loading model")
    ML_MODEL = load("deployed_models/imb_recall_precision.joblib")

    global MODEL_THRESHOLD
    if CHAIN_ID == 1:
        MODEL_THRESHOLD = MODEL_THRESHOLD_ETH
    else:
        MODEL_THRESHOLD = MODEL_THRESHOLD_DEFAULT
    global MODEL_PRECISION_THRESHOLD
    MODEL_PRECISION_THRESHOLD = MODEL_THRESHOLD_ETH_PRECISION  # From this threshold on, the model is very precise. Only use for eth
    logger.info(f"Model threshold: {MODEL_THRESHOLD}. Using eth model for recall")

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON["apiKeys"]["ZETTABLOCK"]
    global ENV
    if 'production' in os.environ.get('NODE_ENV', ''):
        ENV = 'production'
    else:
        ENV = 'dev'


def exec_model(w3, opcodes: str, contract_creator: str) -> tuple:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    t = time.time()
    score = None
    features, opcode_addresses = get_features(w3, opcodes, contract_creator)
    t1 = time.time()
    score = ML_MODEL.predict_proba([features])[0][1]
    t2 = time.time()
    score = round(score, 4)
    if ENV == 'dev':
        logger.info(f"Model Timing:\t Time taken to get features: {t1 - t};\t Time taken to predict: {t2 - t1};\t Total time: {t2 - t}")
    return score, opcode_addresses


def detect_malicious_contract_tx(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    t0 = time.time()
    malicious_findings = []

    previous_contracts = []
    all_creation_bytecodes = {}
    repeated_bytecodes = {}
    created_contract_address = None
    for trace in transaction_event.traces:
        if trace.type == "create":
            created_contract_address = (
                trace.result.address if trace.result else None
            )
            error = trace.error if trace.error else None
            logger.info(f"Contract created {created_contract_address}")
            if created_contract_address is None:
                logger.info(f"Trace was None")
                continue
            if error is not None:
                if transaction_event.from_ == trace.action.from_:
                    nonce = transaction_event.transaction.nonce
                    contract_address = calc_contract_address(w3, trace.action.from_, nonce)
                else:
                    # For contracts creating other contracts, get the nonce using Web3
                    nonce = w3.eth.getTransactionCount(Web3.toChecksumAddress(trace.action.from_), transaction_event.block_number)
                    contract_address = calc_contract_address(w3, trace.action.from_, nonce - 1)

                logger.warn(
                    f"Contract {contract_address} creation failed with tx {trace.transaction_hash}: {error}"
                )
            if created_contract_address.lower() in previous_contracts:
                if ENV == 'dev':
                    logger.info(f"Contract {created_contract_address} was already created")
                continue
            previous_contracts.append(created_contract_address.lower())
            # creation bytecode contains both initialization and run-time bytecode.
            creation_bytecode = trace.action.init
            if creation_bytecode in all_creation_bytecodes.values():
                if ENV == 'dev':
                    logger.info(f"Contract {created_contract_address} was already created")
                original_contract_address = list(all_creation_bytecodes.keys())[list(all_creation_bytecodes.values()).index(creation_bytecode)]
                if original_contract_address not in repeated_bytecodes.keys():
                    repeated_bytecodes[original_contract_address] = {}
                if trace.action.from_ not in repeated_bytecodes[original_contract_address].keys():
                    repeated_bytecodes[original_contract_address][trace.action.from_] = []
                repeated_bytecodes[original_contract_address][trace.action.from_].append(created_contract_address)
                continue
            all_creation_bytecodes[created_contract_address] = creation_bytecode
            for finding in detect_malicious_contract(
                w3,
                trace.action.from_,
                created_contract_address,
                creation_bytecode,
                error=error,
            ):
                finding.addresses = [trace.action.from_, created_contract_address]
                funding_alerts = check_funding_labels(trace.action.from_)
                if len(funding_alerts) > 0:
                    finding.severity = FindingSeverity.Critical
                    finding.metadata["funding_alerts"] = ','.join(funding_alerts)
                if float(finding.metadata['model_score']) >= MODEL_PRECISION_THRESHOLD and CHAIN_ID == 1:
                    finding.severity = FindingSeverity.Critical
                    finding.metadata['high_precision_model'] = True
                if finding.severity == FindingSeverity.Critical:
                    # only raise alerts for critical findings
                    malicious_findings.append(finding)
    # Fake loop tp break out if the contract here has already been analyzed
    for _ in range(1):
        if transaction_event.to is None:
            nonce = transaction_event.transaction.nonce
            created_contract_address = calc_contract_address(
                w3, transaction_event.from_, nonce
            )
            if created_contract_address.lower() in previous_contracts:
                break
            logger.info(f"Contract created {created_contract_address}")
            previous_contracts.append(created_contract_address.lower())
            creation_bytecode = transaction_event.transaction.data
            for finding in detect_malicious_contract(
                w3,
                transaction_event.from_,
                created_contract_address,
                creation_bytecode,
            ):
                finding.addresses = [transaction_event.from_, created_contract_address]
                funding_alerts = check_funding_labels(transaction_event.from_)
                if len(funding_alerts) > 0:
                    finding.severity = FindingSeverity.Critical
                    finding.metadata["funding_alerts"] = ','.join(funding_alerts)
                if float(finding.metadata['model_score']) >= MODEL_PRECISION_THRESHOLD and CHAIN_ID == 1:
                    finding.severity = FindingSeverity.Critical
                    finding.metadata['high_precision_model'] = True
                if finding.severity == FindingSeverity.Critical:
                    # only raise alerts for critical findings
                    malicious_findings.append(finding)

    all_findings = malicious_findings
    if len(repeated_bytecodes) > 0:
        if ENV == 'dev':
            logger.info(f"Repeated bytecodes: {repeated_bytecodes}")
        for finding in all_findings:
            finding_contract = finding.description.split(' ')[-1]
            finding_from = finding.description.split(' ')[0]
            if finding_contract in repeated_bytecodes.keys():
                if finding_from in repeated_bytecodes[finding_contract].keys():
                    finding.description += f" and reused by {', '.join(repeated_bytecodes[finding_contract][finding_from])}"
                    finding.addresses += repeated_bytecodes[finding_contract][finding_from]
    if ENV == 'dev' and created_contract_address:
        logger.info(f"Time taken to complete process: {time.time() - t0}")
    # Reduce findings to 10 because we cannot return more than 10 findings per request
    return all_findings[:10]


def detect_malicious_contract(
    w3, from_, created_contract_address, code, error=None
) -> list:
    findings = []

    if created_contract_address is not None and code is not None:
        if len(code) > BYTE_CODE_LENGTH_THRESHOLD:
            try:
                opcodes = EvmBytecode(code).disassemble()
            except Exception as e:
                logger.warn(f"Error disassembling evm bytecode: {e}")

            (
                model_score,
                opcode_addresses,
            ) = exec_model(w3, opcodes, from_)
            function_signatures = get_function_signatures(w3, opcodes)
            logger.info(f"{created_contract_address}: score={model_score}")

            if model_score is None or model_score < MODEL_THRESHOLD:
                if ENV == 'dev':
                    logger.info(f"Score is less than threshold: {model_score} < {MODEL_THRESHOLD}. Not creating alert.")
                return []
            # obtain all the addresses contained in the created contract and propagate to the findings
            # We only do it if the model score is above the threshold
            env_t = time.time()
            storage_addresses = get_storage_addresses(w3, created_contract_address)
            if ENV == 'dev':
                logger.info(f"Time taken to get storage addresses: {time.time() - env_t}")            
            finding = ContractFindings(
                from_,
                created_contract_address,
                set.union(storage_addresses, opcode_addresses),
                function_signatures,
                model_score,
                MODEL_THRESHOLD,
                error=error,
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
    return findings


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


def check_funding(address: str, n_days: int=1):
    t = time.time()
    bots = FUNDING_BOTS
    query = {
        "first": 20,
        "bot_ids": bots,
        "created_since": n_days*24*60*60*1000,
        "addresses": [address],
    }
    alert_hashes = []
    for _ in range(2):
        try:
            alerts = forta_agent.get_alerts(query)
            alert_hashes += [alert.hash for alert in alerts.alerts if 'funding' in alert.name.lower() and 
                             alert.description.split(" ")[0].lower() == address.lower()]
            break
        except:
            continue
    if ENV == 'dev':
        logger.info(f"Time taken to get alerts: {time.time() - t};\tN_alerts: {len(alert_hashes)};\tAddress: {address}")
    return alert_hashes


def check_funding_labels(address: str, n_days: int=365):
    t = time.time()
    bots = FUNDING_BOTS
    query = {
        "first": 5,
        "source_ids": bots,
        "created_since": n_days*24*60*60*1000,
        "entities": [address],
        "state": True,
    }
    labels_hashes = []
    for _ in range(2):
        try:
            labels = forta_agent.get_labels(query)
            labels_hashes += [label.source.alert_hash for label in labels.labels if 'attacker' in label.label]
            break
        except:
            continue
    if ENV == 'dev':
        logger.info(f"Time taken to get labels: {time.time() - t};\tN_labels: {len(labels_hashes)};\tAddress: {address}")
    return labels_hashes
