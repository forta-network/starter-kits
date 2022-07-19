import pickle
from timeit import default_timer as timer

from .utils.constants import ANOMALY_THRESHOLD, ERC20_TRANSFER_EVENT, MODEL_FEATURES
from .utils.data_processing import get_features
from .utils.findings import AnomalousTransaction, NormalTransaction, InvalidModelFeatures
from .utils.logger import logger


ML_MODEL = None


def initialize():
    """
    this function initializes the ml model
    """
    global ML_MODEL
    logger.info('Start loading model')
    with open('isolation_forest.pkl', 'rb') as f:
        ML_MODEL = pickle.load(f)
    logger.info('Complete loading model')

def get_prediction(features) -> tuple:
    start = timer()
    model_input = [[features.get(key, 0) for key in MODEL_FEATURES]]
    # score_samples output the opposite of the anomaly score defined in the original paper.
    # https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf
    raw_score = ML_MODEL.score_samples(model_input)[0]
    # normalize to return score between 0 and 1 (inclusive)
    normalized_score = abs(raw_score)
    prediction = 'ANOMALY' if normalized_score >= ANOMALY_THRESHOLD else 'NORMAL'
    end = timer()
    return normalized_score, prediction, end - start

def handle_transaction(transaction_event):
    findings = []

    transfer_events = transaction_event.filter_log(ERC20_TRANSFER_EVENT)
    from_address = transaction_event.from_

    if len(transfer_events) > 0:
        valid_features, features = get_features(from_address, transaction_event.timestamp, transfer_events)
        metadata = {'from': from_address}
        metadata.update(features)

        if valid_features:
            anomaly_score, prediction_label, pred_response_time = get_prediction(features)
            metadata['prediction'] = prediction_label
            metadata['anomaly_score'] = round(anomaly_score, 3)
            metadata['model_pred_response_time_sec'] = pred_response_time

            if prediction_label == 'ANOMALY':
                findings.append(AnomalousTransaction(metadata, from_address).emit_finding())
            else:
                findings.append(NormalTransaction(metadata, from_address).emit_finding())
        else:
            findings.append(InvalidModelFeatures(metadata, from_address).emit_finding())

    return findings
