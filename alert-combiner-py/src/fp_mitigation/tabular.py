import pickle

from src.constants import FP_MODELS_PATH


class Tabular:
    def __init__(self) -> None:
        models = {}
        for path in FP_MODELS_PATH:
            imb = path.split('/')[-1]
            imb = imb.split('.')[0]
            with open(path, 'rb') as f:
                models[imb] = pickle.load(f)
        self.models = models
        
    def predict_fp(self, encoding):
        preds = {}
        for imb, model in self.models.items():
            preds[imb] = model.predict_proba(encoding.reshape(1, -1))
        return preds
