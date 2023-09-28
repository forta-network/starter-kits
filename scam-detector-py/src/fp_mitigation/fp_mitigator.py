import logging
import numpy as np

from src.fp_mitigation.autoencoder import AE
from src.fp_mitigation.download_data import DownloadData
from src.fp_mitigation.tabular import Tabular


class FPMitigator:
    def __init__(self, secrets, chain_id) -> None:
        self.download_data = DownloadData(secrets)
        self.autoencoder = AE()
        self.tabular = Tabular()
        self.chain_id = chain_id

    def mitigate_fp(self, address, alert_id):
        if self.chain_id != 1:
            logging.info(f"Chain id {self.chain_id} is not supported. fp-mitigation")
            return None
        in_data = self.download_data.create_graph_around_address(address)
        if in_data is None:
            return None
        embeddings = self.autoencoder.encode(in_data)
        embeddings_concatenated = np.concatenate([embeddings['address'], embeddings['transaction']])
        if alert_id in ['SCAM-DETECTOR-ADDRESS-POISONING']:
            return None
        preds = self.tabular.predict_fp(embeddings_concatenated, alert_id)
        logging.info(f"FP Mitigation for address {address} and alert {alert_id}: {preds}.fp-mitigation")
        alert_preds = np.mean([pred[0][1] for pred in preds.values()])
        return alert_preds
