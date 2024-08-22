import forta_agent
from forta_agent import get_json_rpc_url, EntityType, FindingSeverity
from joblib import load, parallel_config
from evmdasm import EvmBytecode
from web3 import Web3
from os import environ
import time
import os
import json

from src.constants import (
    BYTE_CODE_LENGTH_THRESHOLD,
    MODEL_THRESHOLD_ETH,
    MODEL_THRESHOLD_DEFAULT,
    MODEL_THRESHOLD_ETH_PRECISION,
    MODEL_THRESHOLD_DEFAULT_PRECISION,
    FUNDING_BOTS,
    MODEL_INFO_THRESHOLD,
    MODEL_PATH,
    HIGH_PRECISION_MODEL_PATH,
    FUNDING_TIME,
    EXTRA_TIME_BOTS,
    EXTRA_TIME_DAYS,
    ETH_BLOCKS_IN_ONE_DAY,
    THREE_SECOND_BLOCKS_IN_ONE_DAY
)
from src.findings import ContractFindings
from src.logger import logger
from src.utils import (
    calc_contract_address,
    get_features,
    get_function_signatures,
    get_storage_addresses,
    is_contract,
    get_tp_attacker_list,
    update_tp_attacker_list
)
from src.storage import get_secrets

SECRETS_JSON = get_secrets()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
ML_MODEL = None


def initialize():
    """
    this function loads the ml model, fetches the list of true positive attackers,
    and returns `alert_config` to subscribe to the Suspicious Funding's "MALICIOUS-FUNDING"
    alert id.
    """

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    global ML_MODEL
    logger.info("Start loading model")
    ML_MODEL = load(MODEL_PATH)
    global ML_MODEL_HIGH_PRECISION
    if HIGH_PRECISION_MODEL_PATH == MODEL_PATH:
        logger.info("Using the same model for high precision")
        ML_MODEL_HIGH_PRECISION = ML_MODEL
    else:
        logger.info("Loading high precision model")
        ML_MODEL_HIGH_PRECISION = load(HIGH_PRECISION_MODEL_PATH)

    global MODEL_THRESHOLD
    global MODEL_PRECISION_THRESHOLD
    if CHAIN_ID == 1:
        MODEL_THRESHOLD = MODEL_THRESHOLD_ETH
        MODEL_PRECISION_THRESHOLD = MODEL_THRESHOLD_ETH_PRECISION
    else:
        MODEL_THRESHOLD = MODEL_THRESHOLD_DEFAULT
        MODEL_PRECISION_THRESHOLD = MODEL_THRESHOLD_DEFAULT_PRECISION
    logger.info(f"Model threshold: {MODEL_THRESHOLD}. Threshold for high precision: {MODEL_PRECISION_THRESHOLD}")

    global ENV
    if 'production' in os.environ.get('NODE_ENV', ''):
        ENV = 'production'
    else:
        ENV = 'dev'
    logger.info(f"Environment: {ENV}")

    global BETA
    package = json.load(open('package.json'))
    BETA = 'beta' in package['name']
    logger.info(f"Beta: {BETA}")

    global TP_ATTACKER_LIST
    TP_ATTACKER_LIST = get_tp_attacker_list()

    alert_config = {
        "alertConfig": {
            "subscriptions": [
                {
                    "botId": FUNDING_BOTS[6],
                    "alertId": "MALICIOUS-FUNDING"
                }
            ]
        }
    }
    return alert_config


def exec_model(w3, opcodes: str, contract_creator: str) -> tuple:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    t_aux = None
    t = time.time()
    score = None
    features, opcode_addresses = get_features(w3, opcodes, contract_creator)
    t1 = time.time()
    with parallel_config(backend='threading'):
        score = ML_MODEL.predict_proba([features])[0][1]
        if MODEL_PATH != HIGH_PRECISION_MODEL_PATH:
            t_aux = time.time()
            score_high_precision = ML_MODEL_HIGH_PRECISION.predict_proba([features])[0][1]
            if ENV == 'dev':
                logger.info(f"High precision model score: {score_high_precision}")
            if score_high_precision >= MODEL_PRECISION_THRESHOLD:
                # If the high precision model is over the treshold, we use that score
                score = score_high_precision
    t2 = time.time()
    score = round(score, 4)
    if ENV == 'dev':
        if t_aux is None:
            logger.info(f"Model Timing:\t Time taken to get features: {t1 - t};\t Time taken to predict: {t2 - t1};\t Total time: {t2 - t}")
        else:
            logger.info(f"Model Timing:\t Time taken to get features: {t1 - t};\t Time taken to predict: {t_aux - t1};\t Time taken to predict high precision: {t2 - t_aux};\t Total time: {t2 - t}")
    return score, opcode_addresses


def detect_malicious_contract_tx(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    t0 = time.time()
    all_findings = []

    previous_contracts = []
    all_creation_bytecodes = {}
    repeated_bytecodes = {}
    created_contract_address = None
    tx_timestamp = transaction_event.timestamp * 1000
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
                if finding.severity == FindingSeverity.Critical:
                    # We priorize when there are critical findings
                    funding_alerts, funding_labels = check_funding_labels(trace.action.from_, tx_timestamp=tx_timestamp, n_days=FUNDING_TIME,
                                                                          extra_time_bots=EXTRA_TIME_BOTS, extra_time=EXTRA_TIME_DAYS)
                    if len(funding_labels) > 0:
                        finding.metadata["funding_alerts"] = ','.join(funding_alerts)
                        finding.metadata["funding_labels"] = ','.join(funding_labels)
                    if float(finding.metadata['model_score']) >= MODEL_PRECISION_THRESHOLD:
                        finding.metadata['high_precision_model'] = True
                    # If the model is working in high precision, or it has a 1-day funding alert, we raise the alert and continue
                    if 'high_precision_model' in finding.metadata.keys() or 'funding_labels' in finding.metadata.keys() or 'known_past_attacker' in finding.metadata.keys():
                        # if critical alert raised, no need to continue loop's current iteration
                        all_findings.append(finding)
                        continue
                # This should only trigger in beta and if no critical alert has been raised,
                # due to `continue`ing once critical alert raised
                if BETA:
                    if ENV == 'dev':
                        logger.info(f"Checking funding alerts for {trace.action.from_}")
                    funding_alerts, funding_labels = check_funding_labels(trace.action.from_, tx_timestamp=tx_timestamp, n_days=365)
                    if len(funding_labels) > 0:
                        finding.metadata["funding_alerts"] = ','.join(funding_alerts)
                        finding.metadata["funding_labels"] = ','.join(funding_labels)
                        finding.labels = []
                        finding.alert_id = "EARLY-AD-INFO"
                        finding.severity = FindingSeverity.Info
                        all_findings.append(finding)
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
                if finding.severity == FindingSeverity.Critical:
                    # We priorize when there are critical findings
                    funding_alerts, funding_labels = check_funding_labels(transaction_event.from_, tx_timestamp=tx_timestamp, n_days=FUNDING_TIME, 
                                                                          extra_time_bots=EXTRA_TIME_BOTS, extra_time=EXTRA_TIME_DAYS)
                    if len(funding_labels) > 0:
                        finding.metadata["funding_alerts"] = ','.join(funding_alerts)
                        finding.metadata["funding_labels"] = ','.join(funding_labels)
                    if float(finding.metadata['model_score']) >= MODEL_PRECISION_THRESHOLD:
                        finding.metadata['high_precision_model'] = True
                    # If the model is working in high precision, or it has a 1-day funding alert, we raise the alert and continue
                    if 'high_precision_model' in finding.metadata.keys() or 'funding_labels' in finding.metadata.keys() or 'known_past_attacker' in finding.metadata.keys():
                        # if critical alert raised, no need to continue loop's current iteration
                        all_findings.append(finding)
                        continue
                # This should only trigger in beta and if no critical alert has been raised,
                # due to `continue`ing once critical alert raised
                if BETA:
                    if ENV == 'dev':
                        logger.info(f"Checking funding labels for {transaction_event.from_}")
                    funding_alerts, funding_labels = check_funding_labels(transaction_event.from_, tx_timestamp=tx_timestamp, n_days=365)
                    if len(funding_labels) > 0:
                        finding.metadata["funding_alerts"] = ','.join(funding_alerts)
                        finding.metadata["funding_labels"] = ','.join(funding_labels)
                        finding.labels = []
                        finding.alert_id = "EARLY-AD-INFO"
                        finding.severity = FindingSeverity.Info
                        all_findings.append(finding)


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
        known_past_attacker = from_ in TP_ATTACKER_LIST

        if (len(code) > BYTE_CODE_LENGTH_THRESHOLD) or known_past_attacker:
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

            if not known_past_attacker:
                if model_score is None or model_score < MODEL_INFO_THRESHOLD:
                    if ENV == 'dev':
                        logger.info(f"Score is less than threshold: {model_score} < {MODEL_INFO_THRESHOLD}. Not creating alert.")
                    return []
                # If we are not in beta, we create alerts if the score is above the threshold
                # or if `from_` is in the True Positive list
                if model_score < MODEL_THRESHOLD and not BETA:
                    if ENV == 'dev':
                        logger.info(f"Score is less than threshold: {model_score} < {MODEL_THRESHOLD} and we are not in beta. Not checking for labels.")
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
                known_past_attacker,
                error=error,
            )
            if (model_score is not None and model_score >= MODEL_INFO_THRESHOLD) or known_past_attacker:
                from_label_type = "eoa" if known_past_attacker or not is_contract(w3, from_) else "contract"
                # If it's a potential alert, we create labels. Otherwise, we don't
                if (model_score >= MODEL_THRESHOLD) or known_past_attacker:
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
                        {
                            "entity": created_contract_address,
                            "entity_type": EntityType.Address,
                            "label": "attacker",
                            "confidence": 1.0 if known_past_attacker else model_score,
                        },
                        {
                            "entity": from_,
                            "entity_type": EntityType.Address,
                            "label": "attacker",
                            "confidence": 1.0 if known_past_attacker else model_score,
                        },
                        ]
                    severity = FindingSeverity.Critical
                else:
                    labels = []
                    severity = FindingSeverity.Info
                findings.append(
                    finding.malicious_contract_creation(
                        severity=severity,
                        labels=labels,
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

def provide_handle_block():
    def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
        findings = []

        # Choosing the denominator based on chain's block time
        # so as to update TP list approx. once daily
        DAILY_BLOCKS_DENOMINATOR = ETH_BLOCKS_IN_ONE_DAY if CHAIN_ID == 1 else THREE_SECOND_BLOCKS_IN_ONE_DAY
        if block_event.block_number % DAILY_BLOCKS_DENOMINATOR == 0:
            global TP_ATTACKER_LIST
            TP_ATTACKER_LIST = update_tp_attacker_list(TP_ATTACKER_LIST)
        return findings
        
    return handle_block


real_handle_block = provide_handle_block()


def handle_block(block_event: forta_agent.block_event.BlockEvent):
    return real_handle_block(block_event)

def provide_handle_alert():
    def handle_alert(alert_event: forta_agent.alert_event.AlertEvent) -> list:
        findings = []

        global TP_ATTACKER_LIST
        if alert_event.alert.metadata['sender'].lower() not in TP_ATTACKER_LIST:
            TP_ATTACKER_LIST.append(alert_event.alert.metadata['sender'].lower())
        
        TP_ATTACKER_LIST.append(alert_event.alert.metadata['receiver'].lower())

        return findings

    return handle_alert


real_handle_alert = provide_handle_alert()


def handle_alert(alert_event: forta_agent.alert_event.AlertEvent):
    return real_handle_alert(alert_event)

def check_funding_labels(address: str, tx_timestamp: int, n_days: int=365, extra_time_bots: str=None, extra_time: int=180):
    t = time.time()
    bots = FUNDING_BOTS
    query = {
        "first": 5,
        "source_ids": bots,
        "created_since": tx_timestamp - n_days*24*60*60*1000,
        "entities": [address],
        "state": True,
        "labels": ["attacker"],
    }
    alert_ids = []
    label_ids = []
    for _ in range(2):
        try:
            labels = forta_agent.get_labels(query)
            alert_ids += [label.source.alert_hash for label in labels.labels if 'attacker' in label.label]
            label_ids += [label.id for label in labels.labels if 'attacker' in label.label]
            break
        except:
            continue
    # We only check if there are no alerts and we have bots that should be checked further into the past
    if extra_time_bots is not None and len(alert_ids) == 0:
        query["source_ids"] = extra_time_bots
        query["created_since"] = tx_timestamp - extra_time*24*60*60*1000
        tt = time.time()
        for _ in range(2):
            try:
                labels = forta_agent.get_labels(query)
                alert_ids += [label.source.alert_hash for label in labels.labels if 'attacker' in label.label]
                label_ids += [label.id for label in labels.labels if 'attacker' in label.label]
                break
            except:
                continue
        if ENV == 'dev':
            logger.info(f"Time taken to get extra time labels: {time.time() - tt}")
    if ENV == 'dev':
        logger.info(f"Time taken to get labels: {time.time() - t};\tN_labels: {len(alert_ids)};\tAddress: {address}")
    return alert_ids, label_ids