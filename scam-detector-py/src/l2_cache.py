# Copyright 2022 The Forta Foundation

import logging
import os
import time
import pickle
import requests
import traceback
import forta_agent

DATABASE = "https://research.forta.network/database/bot/"
VERSION = "V10"

from src.utils import Utils

class L2Cache:
    MAX_RETRIES = 3

    @staticmethod
    def write(obj: object, chain_id: int, key: str):
        key = f"{VERSION}-{key}"
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            attempt = 0  
            while attempt < L2Cache.MAX_RETRIES:
                try:
                    logging.info(f"Persisting {key} using API")
                    bytes = pickle.dumps(obj)
                    token = forta_agent.fetch_jwt({})

                    headers = {"Authorization": f"Bearer {token}"}
                    res = requests.post(f"{DATABASE}{key}_{chain_id}", data=bytes, headers=headers)
                    if res.status_code != 200:
                        Utils.ERROR_CACHE.add(Utils.alert_error(f'Error {res.status_code} while persisting key {key} to DB.', "l2_cache.write.internal", ""))
                    logging.info(f"Persisting {key}_{chain_id} to database. Response: {res}")
                    break
                except Exception as e:
                    logging.warn(f"Exception in persist {e}")
                    attempt += 1 
                    time.sleep(0.2)
                    if attempt == L2Cache.MAX_RETRIES:
                        Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "l2_cache.write (max retries reached)", traceback.format_exc()))

        else:
            logging.info(f"Persisting {key}_{chain_id} locally")
            pickle.dump(obj, open(key, "wb"))

    @staticmethod
    def remove(chain_id: int, key: str):
        key = f"{VERSION}-{key}"
        if not ('NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV')):
            if os.path.exists(key):
                os.remove(key)

    @staticmethod
    def load(chain_id: int, key: str) -> object:
        key = f"{VERSION}-{key}"
        if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV'):
            attempt = 0
            while attempt < L2Cache.MAX_RETRIES:
                try:
                    logging.info(f"Loading {key}_{chain_id}  using API")
                    token = forta_agent.fetch_jwt({})
                    headers = {"Authorization": f"Bearer {token}"}
                    res = requests.get(f"{DATABASE}{key}_{chain_id}", headers=headers)
                    logging.info(f"Loaded {key}_{chain_id} . Response: {res}")
                    if res.status_code == 200 and len(res.content) > 0:
                        return pickle.loads(res.content)
                    else:
                        Utils.ERROR_CACHE.add(Utils.alert_error(f'request DB {res.status_code}. key {key} doesnt exist.', "l2_cache.load", ""))
                        logging.info(f"{key} does not exist")
                        break
                except Exception as e:
                    logging.warn(f"Exception in load {e}")
                    attempt += 1
                    time.sleep(0.2)
                    if attempt == L2Cache.MAX_RETRIES:
                        Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "l2_cache.load (max retries reached)", traceback.format_exc()))
                        break

        else:
            # load locally
            logging.info(f"Loading {key}_{chain_id} locally")
            if os.path.exists(key):
                return pickle.load(open(key, "rb"))
            else:
                logging.info(f"File {key} does not exist")
        return None