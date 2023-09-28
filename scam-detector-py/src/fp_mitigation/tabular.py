import pickle
import numpy as np

from src.constants import OHE_PATH, FP_MODELS_PATH


class Tabular:
    def __init__(self) -> None:
        models = {}
        for path in FP_MODELS_PATH:
            imb = path.split('/')[-1]
            imb = imb.split('.')[0]
            with open(path, 'rb') as f:
                models[imb] = pickle.load(f)
        self.models = models
        with open(OHE_PATH, 'rb') as f:
            self.ohe = pickle.load(f)
        
    def predict_fp(self, encoding, alert_id=None):
        preds = {}
        if alert_id is None:
            raise ValueError("alert_id should not be None")
        ohe_alert = self.ohe.transform(np.array([alert_id]).reshape(1, 1)).toarray()
        for imb, model in self.models.items():
            embeddings_ohe = np.concatenate((encoding.reshape(1, -1), ohe_alert), axis=1)
            preds[imb] = model.predict_proba(embeddings_ohe)
        return preds
