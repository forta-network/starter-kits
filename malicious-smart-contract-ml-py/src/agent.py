import forta_agent
from forta_agent import get_json_rpc_url, EntityType
from joblib import load
from evmdasm import EvmBytecode
from web3 import Web3
from os import environ


from src.constants import (
    BYTE_CODE_LENGTH_THRESHOLD,
    MODEL_THRESHOLD_DICT,
    SAFE_CONTRACT_THRESHOLD,
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

    global MODEL_THRESHOLD
    MODEL_THRESHOLD = MODEL_THRESHOLD_DICT.get(str(CHAIN_ID), 0.3)
    logger.info(f"Model threshold: {MODEL_THRESHOLD}")

    global ML_MODEL
    logger.info("Start loading model")
    try:
        logger.info(f"Loading model for chain {CHAIN_ID}")
        ML_MODEL = load(f"deployed_models/voting_clf_{CHAIN_ID}.joblib")
    except:
        logger.info("Model not found, loading default model")
        ML_MODEL = load("malicious_non_token_model_02_07_23_exp2.joblib")
    logger.info("Complete loading model")

    global ML_MODEL_BACKUP
    global MODEL_THRESHOLD_BACKUP
    if CHAIN_ID == 1:
        logger.info(f"Chain id is {CHAIN_ID}. We will load the imbalanced model for improved recall")
        ML_MODEL_BACKUP = load("deployed_models/lgbm_backmodel.joblib")
        MODEL_THRESHOLD_BACKUP = 0.5
    elif CHAIN_ID != 1:
        logger.info(f"Chain id is {CHAIN_ID}. We will load also the eth model for backup")
        ML_MODEL_BACKUP = load("deployed_models/voting_clf_1.joblib")
        MODEL_THRESHOLD_BACKUP = 0.4
    logger.info(f"Alternative model loaded for backup with threshold {MODEL_THRESHOLD_BACKUP}")

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON["apiKeys"]["ZETTABLOCK"]


def exec_model(w3, opcodes: str, contract_creator: str) -> tuple:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    score = None
    features, opcode_addresses = get_features(w3, opcodes, contract_creator)
    score = ML_MODEL.predict_proba([features])[0][1]
    score = round(score, 4)

    return score, opcode_addresses


def exec_model_backup(w3, opcodes: str, contract_creator: str) -> tuple:
    """
    this function executes the model to obtain the score for the contract
    :return: score: float
    """
    score = None
    features, opcode_addresses = get_features(w3, opcodes, contract_creator)
    score = ML_MODEL_BACKUP.predict_proba([features])[0][1]
    score = round(score, 4)

    return score, opcode_addresses


def detect_malicious_contract_tx(
    w3, transaction_event: forta_agent.transaction_event.TransactionEvent
) -> list:
    malicious_findings = []
    safe_findings = []


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

            # creation bytecode contains both initialization and run-time bytecode.
            creation_bytecode = trace.action.init
            for finding in detect_malicious_contract(
                w3,
                trace.action.from_,
                created_contract_address,
                creation_bytecode,
                error=error,
            ):
                if finding.alert_id == "SUSPICIOUS-CONTRACT-CREATION":
                    if check_funding(trace.action.from_):
                        logger.info(f"Contract {created_contract_address} was funded by malicious methods.")
                        finding.metadata["malicious_funding"] = 'yes'
                    malicious_findings.append(finding)
                else:
                    safe_findings.append(finding)
                    if check_funding(trace.action.from_):
                        logger.info(f"Contract {created_contract_address} was funded by malicious methods but the contract was deemed safe")

    if transaction_event.to is None:
        nonce = transaction_event.transaction.nonce
        created_contract_address = calc_contract_address(
            w3, transaction_event.from_, nonce
        )
        logger.info(f"Contract created {created_contract_address}")
        creation_bytecode = transaction_event.transaction.data
        for finding in detect_malicious_contract(
            w3,
            transaction_event.from_,
            created_contract_address,
            creation_bytecode,
        ):
            if finding.alert_id == "SUSPICIOUS-CONTRACT-CREATION":
                if check_funding(transaction_event.from_):
                    logger.info(f"Contract {created_contract_address} was funded by malicious methods.")
                    finding.metadata["malicious_funding"] = 'yes'
                malicious_findings.append(finding)
            else:
                safe_findings.append(finding)
                if check_funding(transaction_event.from_):
                    logger.info(f"Contract {created_contract_address} was funded by malicious methods but the contract was deemed safe")

    # Reduce findings to 10 because we cannot return more than 10 findings per request
    return (malicious_findings + safe_findings)[:10]


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
            # obtain all the addresses contained in the created contract and propagate to the findings
            storage_addresses = get_storage_addresses(w3, created_contract_address)
            (
                model_score,
                opcode_addresses,
            ) = exec_model(w3, opcodes, from_)
            function_signatures = get_function_signatures(w3, opcodes)
            logger.info(f"{created_contract_address}: score={model_score}")

            model_score_backup = None
            finding = None
            if model_score < MODEL_THRESHOLD:
                model_score_backup, opcode_addresses_backup = exec_model_backup(w3, opcodes, from_)
                logger.info(f"{created_contract_address}: Backup score={model_score_backup}")
                if model_score_backup >= MODEL_THRESHOLD_BACKUP:
                    logger.info(f"{created_contract_address}: Backup model triggered")
                    finding = ContractFindings(
                        from_,
                        created_contract_address,
                        set.union(storage_addresses, opcode_addresses_backup),
                        function_signatures,
                        model_score_backup,
                        MODEL_THRESHOLD_BACKUP,
                        error=error,
                    )
                    finding.metadata["backup"] = 'yes'
            if finding is None:
                finding = ContractFindings(
                    from_,
                    created_contract_address,
                    set.union(storage_addresses, opcode_addresses),
                    function_signatures,
                    model_score,
                    MODEL_THRESHOLD,
                    error=error,
                )
            if model_score is not None or model_score_backup is not None:
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
                elif model_score_backup is not None:
                    if model_score_backup >= MODEL_THRESHOLD_BACKUP:
                        labels.extend(
                            [
                                {
                                    "entity": created_contract_address,
                                    "entity_type": EntityType.Address,
                                    "label": "attacker",
                                    "confidence": model_score_backup,
                                },
                                {
                                    "entity": from_,
                                    "entity_type": EntityType.Address,
                                    "label": "attacker",
                                    "confidence": model_score_backup,
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
                    findings.append(finding.non_malicious_contract_creation(CHAIN_ID))

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


def check_funding(address: str):
    bots = ['0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400',
            "0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb", 
            "0xdccd708fc89917168f3a793c605e837572c01a40289c063ea93c2b74182cd15f",
            "0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef",
            "0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46",
            "0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058",
            "0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e"]
    query = {
        "first": 100,
        "bot_ids": bots,
        "created_since": 5*24*60*60*1000,
        "addresses": [address],
    }
    alerts = forta_agent.get_alerts(query)
    logger.info(f"Alerts: {alerts.alerts}")
    if len(alerts.alerts) > 0:
        return True
    else:
        return False
