from os import environ
from joblib import load
from timeit import default_timer as timer

import forta_agent
from forta_agent import get_json_rpc_url, EntityType
from hexbytes import HexBytes

import pandas as pd
from web3 import Web3


from src.utils.constants import MODEL_THRESHOLD, MODEL_FEATURES
from src.utils.data_processing import get_features, get_eoa_tx_stats
from src.utils.findings import EoaScammer
from src.utils.logger import logger
from src.utils.storage import get_secrets

SECRETS_JSON = get_secrets()
ML_MODEL = None
web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


def initialize():
    """
    this function loads the ml model.
    """
    global ML_MODEL
    logger.info("Start loading model")
    with open("march-07-2022-easy-ensemble-4.joblib", "rb") as f:
        ML_MODEL = load(f)
    logger.info("Complete loading model")

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON["apiKeys"]["ZETTABLOCK"]


def is_eoa(w3, address) -> bool:
    """
    this function determines whether address is an eoa
    :return: is_eoa: bool
    """
    if address is None:
        return False
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code == HexBytes("0x")


def get_prediction(address, features) -> tuple:
    start = timer()
    model_input = pd.DataFrame([{key: features.get(key, 0) for key in MODEL_FEATURES}])
    prediction_score = ML_MODEL.predict_proba(model_input)[0][1]
    prediction = "PHISHING_SCAMMER" if prediction_score >= MODEL_THRESHOLD else "NORMAL"
    end = timer()
    prediction_time = round(end - start, 3)
    logger.info(f"Prediction time for {address}: {prediction_time}")
    return prediction_score, prediction, prediction_time


def check_scammer(address: str, eoa_stats: dict, chain_id: str):
    model_features, feature_generation_time = get_features(address, eoa_stats)
    if model_features is not None:
        (
            model_score,
            prediction_label,
            pred_response_time,
        ) = get_prediction(address, model_features)
        if prediction_label == "PHISHING_SCAMMER":
            labels = [
                {
                    "entity": address,
                    "entity_type": EntityType.Address,
                    "label": "scammer-eoa",
                    "confidence": round(model_score, 3),
                }
            ]
            metadata = {
                "scammer": address,
                "feature_generation_time_sec": feature_generation_time,
                "prediction_time_sec": pred_response_time,
                "model_score": round(model_score, 3),
            }
            metadata.update(
                {
                    f"feature_{idx}_{name}": value
                    for idx, (name, value) in enumerate(model_features.items())
                    if name in MODEL_FEATURES
                }
            )
            return EoaScammer(metadata, address, labels, chain_id).emit_finding()


def detect_eoa_phishing_scammer(w3, transaction_event):
    findings = []

    value = transaction_event.transaction.value

    if value > 0:
        # check if to is a phishing scammer
        to_address = transaction_event.to

        if is_eoa(w3, to_address):
            to_address_start = timer()
            eoa_stats, eoa_lst = get_eoa_tx_stats([to_address])

            if to_address in eoa_lst:
                finding = check_scammer(
                    to_address,
                    eoa_stats=eoa_stats[eoa_stats["eoa"] == to_address],
                    chain_id=w3.eth.chainId,
                )
                if finding:
                    findings.append(finding)
            to_address_end = timer()
            response_time = round(to_address_end - to_address_start, 3)
            logger.info(f"Finding generation time for {to_address}: {response_time}sec")

        # TODO: check if from is a phishing scammer
        # TODO: commented out for now because it goes over the bot time out limit
        # if is_eoa(w3, from_address):
        #     from_address_start = timer()
        #     eoa_stats, eoa_lst = get_eoa_tx_stats([from_address])
        #     if from_address in eoa_lst:
        #         finding = check_scammer(
        #             from_address,
        #             eoa_stats=eoa_stats[eoa_stats["eoa"] == from_address],
        #             chain_id=w3.eth.chainId,
        #         )
        #         if finding:
        #             findings.append(finding)
        #     from_address_end = timer()
        #     response_time = round(from_address_end - from_address_start, 3)
        #     logger.info(
        #         f"Finding generation time for {from_address}: {response_time}sec"
        #     )

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(
        transaction_event: forta_agent.transaction_event.TransactionEvent,
    ) -> list:
        return detect_eoa_phishing_scammer(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
