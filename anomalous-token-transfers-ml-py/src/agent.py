from datetime import datetime
from timeit import default_timer as timer

import forta_agent
from forta_agent import get_json_rpc_url, EntityType
from web3 import Web3
import dill
import lime.lime_tabular
import numpy as np

from src.utils.constants import ANOMALY_THRESHOLD, ERC20_TRANSFER_EVENT, MODEL_FEATURES
from src.utils.data_processing import get_features, get_anomaly_score, update_tx_counter
from src.utils.findings import (
    AnomalousTransaction,
    NormalTransaction,
    InvalidModelFeatures,
)
from src.utils.logger import logger


ML_MODEL = None
ML_EXPLAINER = None
web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


def initialize():
    """
    this function loads the ml model and explainer.
    """
    global ML_MODEL, ML_EXPLAINER
    logger.info("Start loading model")
    with open("isolation_forest.pkl", "rb") as f:
        ML_MODEL = dill.load(f)
    logger.info("Complete loading model")
    logger.info("Start loading model explainer")
    with open("model_explainer.pkl", "rb") as f:
        ML_EXPLAINER = dill.load(f)
    logger.info("Complete loading model explainer")


def get_explanations(model_input) -> str:
    def prediction_func(x):
        scores = abs(ML_MODEL.score_samples(x))
        class_probabilities = np.array([[1 - score, score] for score in scores])

        return class_probabilities

    explanation = ML_EXPLAINER.explain_instance(
        model_input, prediction_func, num_features=10
    )
    return [str(weighted_feature) for weighted_feature in explanation.as_list()]


def get_prediction(features) -> tuple:
    start = timer()
    model_input = [[features.get(key, 0) for key in MODEL_FEATURES]]
    # score_samples output the opposite of the anomaly score defined in the original paper.
    # https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf
    raw_score = ML_MODEL.score_samples(model_input)[0]
    explanations = get_explanations(
        np.array(model_input).reshape(
            -1,
        )
    )
    # normalize to return score between 0 and 1 (inclusive)
    normalized_score = abs(raw_score)
    prediction = "ANOMALY" if normalized_score >= ANOMALY_THRESHOLD else "NORMAL"
    end = timer()
    return normalized_score, prediction, explanations, end - start


def detect_anomalous_transfer(w3, transaction_event):
    findings = []

    transfer_events = transaction_event.filter_log(ERC20_TRANSFER_EVENT)
    from_address = transaction_event.from_

    if len(transfer_events) > 0:
        date_time = datetime.now()
        date_hour = date_time.strftime("%d/%m/%Y %H:00:00")
        update_tx_counter(date_hour)

        valid_features, features = get_features(
            from_address, transaction_event.timestamp, transfer_events
        )
        metadata = {"from": from_address}
        metadata.update(features)

        if valid_features:
            (
                model_score,
                prediction_label,
                explanations,
                pred_response_time,
            ) = get_prediction(features)
            anomaly_score = get_anomaly_score(w3.eth.chain_id)
            metadata["prediction"] = prediction_label
            metadata["model_score"] = round(model_score, 3)
            metadata["anomaly_score"] = round(anomaly_score, 6)
            metadata["model_pred_response_time_sec"] = pred_response_time
            metadata["model_explanations"] = explanations

            if prediction_label == "ANOMALY":
                labels = [
                    {
                        "entity": transaction_event.hash,
                        "entity_type": EntityType.Transaction,
                        "label": "anomalous",
                        "confidence": round(model_score, 3),
                    }
                ]
                findings.append(
                    AnomalousTransaction(metadata, from_address, labels).emit_finding()
                )
            else:
                findings.append(
                    NormalTransaction(metadata, from_address).emit_finding()
                )
        else:
            findings.append(InvalidModelFeatures(metadata, from_address).emit_finding())

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(
        transaction_event: forta_agent.transaction_event.TransactionEvent,
    ) -> list:
        return detect_anomalous_transfer(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
):
    return real_handle_transaction(transaction_event)
