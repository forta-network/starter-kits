
from ratelimiter import RateLimiter
import requests
import json
import time
from datetime import datetime
from web3 import Web3
import pandas as pd
import logging
from forta_agent import get_labels

class FortaExplorer:

    @staticmethod
    def get_value(items: dict, key: str):
        v = ''
        if items is None:
            return v
        
        if key in items.keys():
            return items[key]

        return v

    @staticmethod
    @RateLimiter(max_calls=1, period=1)
    def get_labels(source_id: str, start_date: datetime, end_date: datetime, entity: str = "", label_query: str = "") -> pd.DataFrame:

        df_forta = pd.DataFrame(columns=['created_at', 'id', 'label', 'source'])

        query = {f'source_ids': [source_id],
            'created_since': int(start_date.timestamp()*1000),
            'created_before': int(end_date.timestamp()*1000),
            'state': True}

        if entity != "":
            query['entities'] = [entity]

        if label_query != "":
            query['labels'] = [label_query]

        response = get_labels(query)

        index = 0
        for label in response.labels:
            
            df_forta.loc[index] = label.created_at, label.id, label, label.source
            index += 1

                
        df_forta['createdAt'] = pd.to_datetime(df_forta['created_at'])
        df_forta['alertId'] = df_forta['source'].apply(lambda x: x.alert_id)
        df_forta['alertHash'] = df_forta['source'].apply(lambda x: x.alert_hash)
        df_forta['chainId'] = df_forta['source'].apply(lambda x: x.chain_id)
        df_forta['labelstr'] = df_forta['label'].apply(lambda x: x.label)
        df_forta['entity'] = df_forta['label'].apply(lambda x: x.entity)
        df_forta['entityType'] = df_forta['label'].apply(lambda x: x.entity_type)
        df_forta['remove'] = df_forta['label'].apply(lambda x: x.remove)
        df_forta['confidence'] = df_forta['label'].apply(lambda x: x.confidence)
        df_forta['metadata'] = df_forta['label'].apply(lambda x: x.metadata)
        df_forta['uniqueKey'] = df_forta['label'].apply(lambda x: getattr(x, 'unique_key', ''))
        df_forta['botVersion'] = df_forta['label'].apply(lambda x: FortaExplorer.get_value(x.metadata, 'bot_version'))

        return df_forta

