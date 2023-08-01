
from ratelimiter import RateLimiter
import requests
import json
import time
from datetime import datetime
from web3 import Web3
import pandas as pd
import logging

class FortaExplorer:

    @staticmethod
    def get_value(items: list, key: str):
        v = ''
        if items is None:
            return v
        
        for item in items:
            if item.startswith(key):
                v = item.split('=')[1]
                break
        return v

    @staticmethod
    @RateLimiter(max_calls=1, period=1)
    def get_labels(source_id: str, start_date: datetime, end_date: datetime, entity: str = "", label_query: str = "") -> pd.DataFrame:
        url = "https://api.forta.network/graphql"
        chunk_size = 8000

        df_forta = pd.DataFrame(columns=['createdAt', 'id', 'label', 'source'])
        json_data = ""
        first_run = True
        count = 0
        while (json_data == "" or json_data['data']['labels']['pageInfo']['hasNextPage']):
            query = """query exampleQuery {
                        labels(
                            input: {
                                LABELS_CLAUSE
                                SOURCEIDS_CLAUSE
                                CREATEDBEFORE_CLAUSE
                                CREATEDSINCE_CLAUSE
                                ENTITY_CLAUSE
                                AFTER_CLAUSE
                                CHUNKSIZE
                                state: true
                            }
                        ) {
                            pageInfo {
                                endCursor {
                                    pageToken
                                }
                                hasNextPage
                            }
                            labels {
                                createdAt
                                id
                                label {
                                    label
                                    metadata
                                    remove
                                    entityType
                                    entity
                                    confidence
                                }
                                source {
                                    chainId
                                    alertHash
                                    alertId
                                }
                            }
                        }
                    }"""

            after_clause = ""
            if(first_run is False):
                pageToken = json_data['data']['labels']['pageInfo']['endCursor']['pageToken']
                after_clause = """after: {{pageToken:"{0}"}}""".format(pageToken)

            # this is a bit hacky
            if label_query != "":
                query = query.replace("LABELS_CLAUSE", f"""labels: ["{label_query}"]""")    
            else: 
                query = query.replace("LABELS_CLAUSE", f"")    
            query = query.replace("SOURCEIDS_CLAUSE", f"""sourceIds: ["{source_id}"]""")
            query = query.replace("ENTITY_CLAUSE", f"""entities: ["{entity}"]""")
            query = query.replace("CREATEDBEFORE_CLAUSE", f"""createdBefore: {int(end_date.timestamp()*1000)}""")
            query = query.replace("CREATEDSINCE_CLAUSE", f"""createdSince: {int(start_date.timestamp()*1000)}""")
            query = query.replace("AFTER_CLAUSE", after_clause)
            query = query.replace("CHUNKSIZE", f"first: {chunk_size}") 

            #print(query)

            retries = 1
            wait = 1
            success = False
            while not success:
                try:
                    count += 1
                    r = requests.post(url, json={'query': query})
                    if r.status_code == 200:
                        success = True
                        if chunk_size < 5000:
                            chunk_size *= 2
                            logging.warning(f"Increasing chunk size to {chunk_size}")
                    else:
                        raise Exception(f"status code: {r.status_code} {r.text}")
                except Exception as e:
                    logging.warning(f"Unable to retrieve alerts: {e}")
                    logging.warning(f"Sleeping {wait}sec. Count {count}.")
                    old_chunk_size = chunk_size
                    chunk_size = int(chunk_size/2)
                    if(chunk_size<1):
                        chunk_size = 1
                    query = query.replace(f"first: {old_chunk_size},", f"first: {chunk_size},") 
                    logging.warning(f"Reducing chunk size to {chunk_size}")
                    time.sleep(wait)
                    retries += 1
                    if retries > 30:
                        raise Exception("Unable to retrieve alerts even after repeated retries. Pls check logs")

            json_data = json.loads(r.text)
            df_data = json_data['data']['labels']['labels']
            df_forta = pd.concat([pd.DataFrame(df_data), df_forta])

            first_run = False
            count += 1

                
        df_forta['createdAt'] = pd.to_datetime(df_forta['createdAt'])
        df_forta['alertId'] = df_forta['source'].apply(lambda x: x['alertId'])
        df_forta['alertHash'] = df_forta['source'].apply(lambda x: x['alertHash'])
        df_forta['chainId'] = df_forta['source'].apply(lambda x: x['chainId'])
        df_forta['labelstr'] = df_forta['label'].apply(lambda x: x['label'])
        df_forta['entity'] = df_forta['label'].apply(lambda x: x['entity'])
        df_forta['entityType'] = df_forta['label'].apply(lambda x: x['entityType'])
        df_forta['remove'] = df_forta['label'].apply(lambda x: x['remove'])
        df_forta['confidence'] = df_forta['label'].apply(lambda x: x['confidence'])
        df_forta['metadata'] = df_forta['label'].apply(lambda x: x['metadata'])
        df_forta['botVersion'] = df_forta['label'].apply(lambda x: FortaExplorer.get_value(x['metadata'], 'bot_version'))

        return df_forta

