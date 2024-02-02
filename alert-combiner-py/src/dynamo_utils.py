import logging
from datetime import datetime
import time
import json
import botocore
import hashlib
import pandas as pd

from src.constants import ALERTS_LOOKBACK_WINDOW_IN_HOURS, DATAFRAME_SIZE_LIMIT, FP_MITIGATION_EXPIRY_IN_HOURS
from src.utils import Utils

TEST_TAG = "attack-detector-test_v3"
PROD_TAG = "attack-detector-prod"

class DynamoUtils:
    chain_id = None

    def __init__(self, tag = TEST_TAG, chain_id = 1):
        self.chain_id = chain_id
        self.tag = tag
        logging.debug(f"Set chain ID = {self.chain_id} and tag = {self.tag} to the DynamoUtils class")
     
    def _get_expiry_offset(self):
        return ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60

    def _get_expires_at(self, alert_created_at=None):
        expiry_offset = self._get_expiry_offset()
        if alert_created_at:
            return int(alert_created_at) + int(expiry_offset)
        else:
            return int(time.time()) + int(expiry_offset)

    def _put_item(self, dynamo, item):
        response = None
        error_message = f'dynamo_utils._put_item'

        # Check if 'cluster' key exists in item
        if 'cluster' in item:
            error_message += f', Cluster: {item["cluster"]}'

        # Check if 'address' key exists in item
        if 'address' in item:
            error_message += f', Address: {item["address"]}'

        try:
            response = dynamo.put_item(Item=item)
            if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
                logging.error(f"Error putting item in dynamoDB: {response}")           
                Utils.ERROR_CACHE.add(Utils.alert_error(f'dynamo_utils._put_item HTTPStatusCode {response["ResponseMetadata"]["HTTPStatusCode"]}', "dynamo_utils._put_item", ""))
            else:
                logging.info(f"Successfully put item in dynamoDB: {response}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ValidationException':
                logging.error(f"ValidationException when calling the PutItem operation: {e}")
                error_message = f'dynamo_utils._put_item'

                if 'cluster' in item:
                    error_message += f', Cluster: {item["cluster"]}'

                if 'address' in item:
                    error_message += f', Address: {item["address"]}'
                Utils.ERROR_CACHE.add(Utils.alert_error(error_message, "dynamo_utils._put_item", ""))
            else:
                logging.error(f"Error putting item in dynamoDB: {e}")
                Utils.ERROR_CACHE.add(Utils.alert_error(f'dynamo_utils._put_item Other Exception {e}', "dynamo_utils._put_item", ""))

    def put_entity_cluster(self, dynamo, alert_created_at_str: str, address: str, cluster: str):
        logging.debug(f"putting entity clustering alert for {address} in dynamo DB")
        alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        logging.debug(f"alert_created_at: {alert_created_at}")
        itemId = f"{self.tag}|{self.chain_id}|entity_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")
        sortIdHash = hashlib.sha256(sortId.encode()).hexdigest()
        
        expiresAt = self._get_expires_at(alert_created_at)
        logging.debug(f"expiresAt: {expiresAt}")
        
        item = {
            "itemId": itemId,
            "sortKey": sortIdHash,
            "address": address,
            "cluster": cluster,
            "expiresAt": expiresAt
        }
        
        self._put_item(dynamo, item)

    def put_fp_mitigation_cluster(self, dynamo, address: str):
        logging.debug(f"putting fp mitigation cluster alert for {address} in dynamo DB")
        itemId = f"{self.tag}|{self.chain_id}|fp_mitigation_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")
        sortIdHash = hashlib.sha256(sortId.encode()).hexdigest()

        # Store for a year
        expiry_offset = FP_MITIGATION_EXPIRY_IN_HOURS * 60 * 60
        expiresAt = int(time.time()) + int(expiry_offset)
        logging.debug(f"expiresAt: {expiresAt}")

        item = {
            "itemId": itemId,
            "sortKey": sortIdHash,
            "address": address,
            "expiresAt": expiresAt
        }

        self._put_item(dynamo, item)

    def put_end_user_attack_cluster(self, dynamo, address: str):
        logging.debug(f"putting end user attack cluster alert for {address} in dynamo DB")
        itemId = f"{self.tag}|{self.chain_id}|end_user_attack_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")
        sortIdHash = hashlib.sha256(sortId.encode()).hexdigest()
        expiresAt = self._get_expires_at()
        logging.debug(f"expiresAt: {expiresAt}")

        item = {
            "itemId": itemId,
            "sortKey": sortIdHash,
            "address": address,
            "expiresAt": expiresAt
        }

        self._put_item(dynamo, item)

    def put_alert_data(self, dynamo, cluster: str, dataframe: pd.DataFrame):
        logging.debug(f"Putting alert data for cluster {cluster} in DynamoDB")
        last_alert_created_at = dataframe["created_at"].iloc[-1].timestamp()
        logging.debug(f"alert_created_at: {last_alert_created_at}")
        itemId = f"{self.tag}|{self.chain_id}|alert"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{cluster}"
        logging.debug(f"sortId: {sortId}")
        sortIdHash = hashlib.sha256(sortId.encode()).hexdigest()
        expiresAt = self._get_expires_at(last_alert_created_at)
        logging.debug(f"expiresAt: {expiresAt}")    
        logging.debug(f"Dataframe length before filtering: {len(dataframe)}")
        expiry_offset = pd.Timedelta(seconds=self._get_expiry_offset())
        dataframe = dataframe[dataframe["created_at"] > (pd.to_datetime(last_alert_created_at, unit='s') - expiry_offset)]
        logging.debug(f"Dataframe length after filtering: {len(dataframe)}")
        dataframe_json = dataframe.to_json(orient="records")
        dataframe_json_size = len(json.dumps(dataframe_json))

        if dataframe_json_size > DATAFRAME_SIZE_LIMIT:
            grouped = dataframe.groupby(['bot_id', 'alert_id'])

            # Function to keep the top half of entries based on 'anomaly_score'
            def reduce_entries(group):
                if len(group) > 1:
                    half = len(group) // 2
                    return group.nsmallest(half, 'anomaly_score')
                else:
                    return group

            # Apply the data reduction function to each group and concatenate the results
            dataframe_to_store = grouped.apply(reduce_entries).reset_index(drop=True)
        else:
            dataframe_to_store = dataframe

        dataframe_to_store_json = dataframe_to_store.to_json(orient="records")

        item = {
            "itemId": itemId,
            "sortKey": sortIdHash,
            "cluster": cluster,
            "dataframe": dataframe_to_store_json,
            "expiresAt": expiresAt
        }

        self._put_item(dynamo, item)

    def put_victim(self, dynamo, transaction_hash: str, metadata: dict):
        logging.debug(f"Putting victim with transaction hash {transaction_hash} in DynamoDB")
        itemId = f"{self.tag}|{self.chain_id}|victim"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{transaction_hash}"
        logging.debug(f"sortId: {sortId}")
        sortIdHash = hashlib.sha256(sortId.encode()).hexdigest()

        expiresAt = self._get_expires_at()
        logging.debug(f"expiresAt: {expiresAt}")

        item = {
            "itemId": itemId,
            "sortKey": sortIdHash,
            "transaction_hash": transaction_hash,
            "metadata": metadata,
            "expiresAt": expiresAt
        }

        self._put_item(dynamo, item)

    def _query_items(self, dynamo, itemId, sortKey=None):
        response = None
        try:
            if sortKey:
                response = dynamo.query(KeyConditionExpression='itemId = :id AND sortKey = :sid',
                                        ExpressionAttributeValues={
                                            ':id': itemId,
                                            ':sid': sortKey
                                        }
                                        )
            else:
                response = dynamo.query(KeyConditionExpression='itemId = :id',
                                        ExpressionAttributeValues={
                                            ':id': itemId,
                                        }
                                        )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ValidationException':
                logging.error(f"ValidationException when calling the Query operation: {str(e)}")
                Utils.ERROR_CACHE.add(Utils.alert_error(f'dynamo_utils._query_items ValidationException (SORT_KEY: {str(sortKey)}, ITEM_ID: {itemId})', "dynamo_utils._query_items", ""))
            else:
                logging.error(f"Error querying items in dynamoDB: {str(e)}")
                Utils.ERROR_CACHE.add(Utils.alert_error(f'dynamo_utils._query_items Other Exception (SORT_KEY: {str(sortKey)}, ITEM_ID: {itemId})', "dynamo_utils._query_items", ""))
            return []

        if response is None:
            return []

        return response.get('Items', [])

    def read_entity_clusters(self, dynamo, address: str) -> dict:
        entity_clusters = dict()
        itemId = f"{self.tag}|{self.chain_id}|entity_cluster"
        sortKey = f"{address}"
        logging.debug(f"Reading entity clusters for address {address}, itemId {itemId}")
        sortIdHash = hashlib.sha256(sortKey.encode()).hexdigest()

        items = self._query_items(dynamo, itemId, sortIdHash)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            entity_clusters[address] = item["cluster"]
        logging.info(f"Read entity clusters for address {address}. Retrieved {len(entity_clusters)} alert_clusters.")
        return entity_clusters

    def read_fp_mitigation_clusters(self, dynamo) -> list:
        fp_mitigation_clusters = []        
        itemId = f"{self.tag}|{self.chain_id}|fp_mitigation_cluster"
        
        items = self._query_items(dynamo, itemId)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            fp_mitigation_clusters.append(item["address"])
        logging.info(f"Read fp mitigation clusters. Retrieved {len(fp_mitigation_clusters)} alert_clusters.")
        return fp_mitigation_clusters
    
    def read_end_user_attack_clusters(self, dynamo) -> list:
        end_user_attack_clusters = []
        itemId = f"{self.tag}|{self.chain_id}|end_user_attack_cluster"
        
        items = self._query_items(dynamo, itemId)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            end_user_attack_clusters.append(item["address"])
        logging.info(f"Read end user attack clusters. Retrieved {len(end_user_attack_clusters)} alert_clusters.")
        return end_user_attack_clusters
    
    def read_alert_data(self, dynamo, cluster: str) -> pd.DataFrame:
        alert_data = pd.DataFrame()
        itemId = f"{self.tag}|{self.chain_id}|alert"
        sortKey = f"{cluster}"
        sortIdHash = hashlib.sha256(sortKey.encode()).hexdigest()
        
        items = self._query_items(dynamo, itemId, sortIdHash)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            dataframe_json = item["dataframe"]
            dataframe = pd.read_json(dataframe_json, orient="records")
            # Convert NaN values to string "NaN"
            dataframe = dataframe.fillna("Nan")           
            # Replace "NaN" with None in each column
            for column in dataframe.columns:
                dataframe[column].replace("Nan", None, inplace=True)

            alert_data = pd.concat([alert_data, dataframe], ignore_index=True)
        logging.info(f"Read alert data for cluster {cluster}. Retrieved {len(alert_data)} alert_data.")
        return alert_data

    def delete_alert_data(self, dynamo, address):
        itemId = f"{self.tag}|{self.chain_id}|alert"
        sortKey = f"{address}"
        logging.debug(f"Deleting alert data for address {address}, itemId {itemId}, sortKey {sortKey}")
        response = dynamo.delete_item(
            Key={
                'itemId': itemId,
                'sortKey': sortKey
            }
        )

        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            logging.error(f"Error deleting alert data for address {address} from DynamoDB: {response}")
            Utils.ERROR_CACHE.add(Utils.alert_error(f'dynamo_utils.delete_alert_data HTTPStatusCode {response["ResponseMetadata"]["HTTPStatusCode"]}', "dynamo_utils.delete_alert_data", ""))
        else:
            logging.info(f"Successfully deleted alert data for address {address} from DynamoDB")

    def read_victims(self, dynamo) -> dict:
        victims = dict()
        itemId = f"{self.tag}|{self.chain_id}|victim"
        
        items = self._query_items(dynamo, itemId)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            victims[item["transaction_hash"]] = item["metadata"]
        logging.info(f"Read victims. Retrieved {len(victims)} victims.")
        return victims
    
    def clean_db(self, dynamo):
        item_types = ['entity_cluster', 'fp_mitigation_cluster', 'end_user_attack_cluster', 'alert', 'victim']
        chain_ids = [1, 10]  # Only chains used in tests

        for chain_id in chain_ids:            
            for item_type in item_types:
                itemId = f"{self.tag}|{chain_id}|{item_type}"
                lastEvaluatedKey = None
                while True:
                    if lastEvaluatedKey:
                        response = dynamo.query(
                            KeyConditionExpression='itemId = :id',
                            ExpressionAttributeValues={
                                ':id': itemId,
                            },
                            ExclusiveStartKey=lastEvaluatedKey
                        )
                    else:
                        response = dynamo.query(
                            KeyConditionExpression='itemId = :id',
                            ExpressionAttributeValues={
                                ':id': itemId,
                            }
                        )

                    for item in response['Items']:
                        dynamo.delete_item(
                            Key={
                                'itemId': item['itemId'],
                                'sortKey': item['sortKey']
                            }
                        )

                    lastEvaluatedKey = response.get('LastEvaluatedKey')
                    if not lastEvaluatedKey:
                        break