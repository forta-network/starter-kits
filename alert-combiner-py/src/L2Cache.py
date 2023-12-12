import logging
import os
import pickle
import requests
import traceback
import forta_agent

from src.utils import Utils

DATABASE = "https://research.forta.network/database/bot/"
VERSION = "V2"
L2_VERSION = "V2.1"

class L2Cache:

    @staticmethod
    def write(obj: object, chain_id: int, key: str):
        key = f"{L2_VERSION}-{key}" if chain_id in (10, 42161) else f"{VERSION}-{key}"
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            try:
                logging.info(f"Persisting {key} using API")
                bytes = pickle.dumps(obj)
                token = forta_agent.fetch_jwt({})

                headers = {"Authorization": f"Bearer {token}"}
                res = requests.post(f"{DATABASE}{key}_{chain_id}", data=bytes, headers=headers)
                logging.info(f"Persisting {key}_{chain_id} to database. Response: {res}")
            except Exception as e:
                logging.warn(f"Exception in persist {e}")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "l2_cache.persist", traceback.format_exc()))
        else:
            logging.info(f"Persisting {key}_{chain_id} locally")
            pickle.dump(obj, open(key, "wb"))

    @staticmethod
    def load(chain_id: int, key: str) -> object:
        key = f"{L2_VERSION}-{key}" if chain_id in (10, 42161) else f"{VERSION}-{key}"
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            try:
                logging.info(f"Loading {key}_{chain_id}  using API")
                token = forta_agent.fetch_jwt({})
                headers = {"Authorization": f"Bearer {token}"}
                res = requests.get(f"{DATABASE}{key}_{chain_id}", headers=headers)
                logging.info(f"Loaded {key}_{chain_id} . Response: {res}")
                if res.status_code == 200 and len(res.content) > 0:
                    return pickle.loads(res.content)
                else:
                    logging.info(f"{key} does not exist")
                    Utils.ERROR_CACHE.add(Utils.alert_error(f'request DB {res.status_code}. key {key} doesnt exist.', "l2_cache.load", ""))
            except Exception as e:
                logging.warn(f"Exception in load {e}")
                Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "l2_cache.load", traceback.format_exc()))
        else:
            # load locally
            logging.info(f"Loading {key}_{chain_id} locally")
            if os.path.exists(key):
                return pickle.load(open(key, "rb"))
            else:
                logging.info(f"File {key} does not exist")
        return None
