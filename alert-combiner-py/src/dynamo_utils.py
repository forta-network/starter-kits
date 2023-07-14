import logging
from datetime import datetime
import time
from src.constants import ALERTS_LOOKBACK_WINDOW_IN_HOURS
import pandas as pd

# TODO: Replace with prod prefix
item_id_prefix = "devdevdev1111"


class DynamoUtils:
    chain_id = None

    def __init__(self, chain_id = 1):
        self.chain_id = chain_id
        logging.debug(f"Set chain ID = {self.chain_id} to the DynamoUtils class")
     
    def _get_expiry_offset(self):
        return ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60

    def _get_expires_at(self, alert_created_at=None):
        expiry_offset = self._get_expiry_offset()
        if alert_created_at:
            return int(alert_created_at) + int(expiry_offset)
        else:
            return int(time.time()) + int(expiry_offset)

    def _put_item(self, dynamo, item):
        response = dynamo.put_item(Item=item)
        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            logging.error(f"Error putting item in dynamoDB: {response}")
        else:
            logging.info(f"Successfully put item in dynamoDB: {response}")

    def put_entity_cluster(self, dynamo, alert_created_at_str: str, address: str, cluster: str):
        logging.debug(f"putting entity clustering alert for {address} in dynamo DB")
        alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        logging.debug(f"alert_created_at: {alert_created_at}")
        itemId = f"{item_id_prefix}|{self.chain_id}|entity_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")
        
        expiresAt = self._get_expires_at(alert_created_at)
        logging.debug(f"expiresAt: {expiresAt}")
        
        item = {
            "itemId": itemId,
            "sortKey": sortId,
            "address": address,
            "cluster": cluster,
            "expiresAt": expiresAt
        }
        
        self._put_item(dynamo, item)

    def put_fp_mitigation_cluster(self, dynamo, address: str):
        logging.debug(f"putting fp mitigation cluster alert for {address} in dynamo DB")
        itemId = f"{item_id_prefix}|{self.chain_id}|fp_mitigation_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")

        expiresAt = self._get_expires_at()
        logging.debug(f"expiresAt: {expiresAt}")

        item = {
            "itemId": itemId,
            "sortKey": sortId,
            "address": address,
            "expiresAt": expiresAt
        }

        self._put_item(dynamo, item)

    def put_end_user_attack_cluster(self, dynamo, address: str):
        logging.debug(f"putting end user attack cluster alert for {address} in dynamo DB")
        itemId = f"{item_id_prefix}|{self.chain_id}|end_user_attack_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")

        expiresAt = self._get_expires_at()
        logging.debug(f"expiresAt: {expiresAt}")

        item = {
            "itemId": itemId,
            "sortKey": sortId,
            "address": address,
            "expiresAt": expiresAt
        }

        self._put_item(dynamo, item)

    def put_alert_data(self, dynamo, cluster: str, dataframe: pd.DataFrame):
        logging.debug(f"Putting alert data for cluster {cluster} in DynamoDB")
        last_alert_created_at = dataframe["created_at"].iloc[-1].timestamp()
        logging.debug(f"alert_created_at: {last_alert_created_at}")
        itemId = f"{item_id_prefix}|{self.chain_id}|alert"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{cluster}"
        logging.debug(f"sortId: {sortId}")
        expiresAt = self._get_expires_at(last_alert_created_at)
        logging.debug(f"expiresAt: {expiresAt}")    
        logging.debug(f"Dataframe length before filtering: {len(dataframe)}")
        expiry_offset = pd.Timedelta(seconds=self._get_expiry_offset())
        dataframe = dataframe[dataframe["created_at"] > (pd.to_datetime(last_alert_created_at, unit='s') - expiry_offset)]
        logging.debug(f"Dataframe length after filtering: {len(dataframe)}")
        dataframe_json = dataframe.to_json(orient="records")
        
        item = {
            "itemId": itemId,
            "sortKey": sortId,
            "cluster": cluster,
            "dataframe": dataframe_json,
            "expiresAt": expiresAt
        }

        self._put_item(dynamo, item)

    def put_victim(self, dynamo, transaction_hash: str, metadata: dict):
        logging.debug(f"Putting victim with transaction hash {transaction_hash} in DynamoDB")
        itemId = f"{item_id_prefix}|{self.chain_id}|victim"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{transaction_hash}"
        logging.debug(f"sortId: {sortId}")

        expiresAt = self._get_expires_at()
        logging.debug(f"expiresAt: {expiresAt}")

        item = {
            "itemId": itemId,
            "sortKey": sortId,
            "transaction_hash": transaction_hash,
            "metadata": metadata,
            "expiresAt": expiresAt
        }

        self._put_item(dynamo, item)

    def _query_items(self, dynamo, itemId, sortKey=None):
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
        return response.get('Items', [])

    def read_entity_clusters(self, dynamo, address: str) -> dict:
        entity_clusters = dict()
        itemId = f"{item_id_prefix}|{self.chain_id}|entity_cluster"
        sortKey = f"{address}"
        logging.debug(f"Reading entity clusters for address {address}, itemId {itemId}")

        items = self._query_items(dynamo, itemId, sortKey)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            entity_clusters[address] = item["cluster"]
        logging.info(f"Read entity clusters for address {address}. Retrieved {len(entity_clusters)} alert_clusters.")
        return entity_clusters

    def read_fp_mitigation_clusters(self, dynamo) -> list:
        fp_mitigation_clusters = []        
        itemId = f"{item_id_prefix}|{self.chain_id}|fp_mitigation_cluster"
        
        items = self._query_items(dynamo, itemId)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            fp_mitigation_clusters.append(item["address"])
        logging.info(f"Read fp mitigation clusters. Retrieved {len(fp_mitigation_clusters)} alert_clusters.")
        return fp_mitigation_clusters
    
    def read_end_user_attack_clusters(self, dynamo) -> list:
        end_user_attack_clusters = []
        itemId = f"{item_id_prefix}|{self.chain_id}|end_user_attack_cluster"
        
        items = self._query_items(dynamo, itemId)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            end_user_attack_clusters.append(item["address"])
        logging.info(f"Read end user attack clusters. Retrieved {len(end_user_attack_clusters)} alert_clusters.")
        return end_user_attack_clusters
    
    def read_alert_data(self, dynamo, cluster: str) -> pd.DataFrame:
        alert_data = pd.DataFrame()
        itemId = f"{item_id_prefix}|{self.chain_id}|alert"
        sortKey = f"{cluster}"
        
        items = self._query_items(dynamo, itemId, sortKey)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            dataframe_json = item["dataframe"]
            dataframe = pd.read_json(dataframe_json, orient="records")
            alert_data = pd.concat([alert_data, dataframe], ignore_index=True)
        logging.info(f"Read alert data for cluster {cluster}. Retrieved {len(alert_data)} alert_data.")
        return alert_data

    def delete_alert_data(self, dynamo, address):
        itemId = f"{item_id_prefix}|{self.chain_id}|alert"
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
        else:
            logging.info(f"Successfully deleted alert data for address {address} from DynamoDB")

    def read_victims(self, dynamo) -> dict:
        victims = dict()
        itemId = f"{item_id_prefix}|{self.chain_id}|victim"
        
        items = self._query_items(dynamo, itemId)

        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            victims[item["transaction_hash"]] = item["metadata"]
        logging.info(f"Read victims. Retrieved {len(victims)} victims.")
        return victims
    
    def clean_db(dynamo):
        item_types = ['entity_cluster', 'fp_mitigation_cluster', 'end_user_attack_cluster', 'alert', 'victim']
        chain_ids = [1, 10]  # Only chains used in tests

        for chain_id in chain_ids:            
            for item_type in item_types:
                itemId = f"{item_id_prefix}|{chain_id}|{item_type}"
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