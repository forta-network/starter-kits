import logging
from boto3.dynamodb.conditions import Key
from datetime import datetime
import time
from src.constants import ALERTS_LOOKBACK_WINDOW_IN_HOURS
import pandas as pd
from src.utils import Utils 

# TODO: Replace with real prefix
item_id_prefix = ""

class DynamoUtils:
    @staticmethod
    def put_entity_cluster(dynamo, alert_created_at_str: str, address: str, cluster: str, chain_id):
        logging.debug(f"putting entity clustering alert for {address} in dynamo DB")
        alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        logging.debug(f"alert_created_at: {alert_created_at}")
        itemId = f"{item_id_prefix}|{chain_id}|entity_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")
        
        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60
        
        expiresAt = int(alert_created_at) + int(expiry_offset)
        logging.debug(f"expiresAt: {expiresAt}")
        response = dynamo.put_item(Item={
            "itemId": itemId,
            "sortKey": sortId,
            "address": address,
            "cluster": cluster,
            "expiresAt": expiresAt
        })

        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            logging.error(f"Error putting entity cluster in dynamoDB: {response}")
            return
        else:
            logging.info(f"Successfully put entity cluster in dynamoDB: {response}")
            return

    @staticmethod
    def put_fp_mitigation_cluster(dynamo, address: str, chain_id):
        logging.debug(f"putting fp mitigation cluster alert for {address} in dynamo DB")
        itemId = f"{item_id_prefix}|{chain_id}|fp_mitigation_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")

        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60

        expiresAt = int(time.time()) + int(expiry_offset)
        logging.debug(f"expiresAt: {expiresAt}")
        response = dynamo.put_item(Item={
            "itemId": itemId,
            "sortKey": sortId,
            "address": address,
            "expiresAt": expiresAt
        })

        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            logging.error(f"Error putting fp mitigation cluster in dynamoDB: {response}")
            return
        else:
            logging.info(f"Successfully put fp mitigation cluster in dynamoDB: {response}")
            return

    @staticmethod
    def put_end_user_attack_cluster(dynamo, address: str, chain_id):
        logging.debug(f"putting end user attack cluster alert for {address} in dynamo DB")
        itemId = f"{item_id_prefix}|{chain_id}|end_user_attack_cluster"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{address}"
        logging.debug(f"sortId: {sortId}")

        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60

        expiresAt = int(time.time()) + int(expiry_offset)
        logging.debug(f"expiresAt: {expiresAt}")
        response = dynamo.put_item(Item={
            "itemId": itemId,
            "sortKey": sortId,
            "address": address,
            "expiresAt": expiresAt
        })

        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            logging.error(f"Error putting end user attack cluster in dynamoDB: {response}")
            return
        else:
            logging.info(f"Successfully put end user attack cluster in dynamoDB: {response}")
            return

    @staticmethod
    def put_alert_data(dynamo, cluster: str, dataframe: pd.DataFrame, chain_id):
        logging.debug(f"Putting alert data for cluster {cluster} in DynamoDB")
        first_alert_created_at = dataframe["created_at"].iloc[0].timestamp()
        logging.debug(f"alert_created_at: {first_alert_created_at}")
        itemId = f"{item_id_prefix}|{chain_id}|alert"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{cluster}"
        logging.debug(f"sortId: {sortId}")

        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60

        expiresAt = int(first_alert_created_at) + int(expiry_offset)
        logging.debug(f"expiresAt: {expiresAt}")
        
        dataframe_json = dataframe.to_json(orient="records")
        
        response = dynamo.put_item(Item={
            "itemId": itemId,
            "sortKey": sortId,
            "cluster": cluster,
            "dataframe": dataframe_json,
            "expiresAt": expiresAt
        })

        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            logging.error(f"Error putting alert data in DynamoDB: {response}")
        else:
            logging.info(f"Successfully put alert data in DynamoDB: {response}")

    @staticmethod   
    def put_victim(dynamo, transaction_hash: str, metadata: dict, chain_id):
        logging.debug(f"Putting victim with transaction hash {transaction_hash} in DynamoDB")
        itemId = f"{item_id_prefix}|{chain_id}|victim"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{transaction_hash}"
        logging.debug(f"sortId: {sortId}")

        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60

        expiresAt = int(time.time()) + int(expiry_offset)
        logging.debug(f"expiresAt: {expiresAt}")
        response = dynamo.put_item(Item={
            "itemId": itemId,
            "sortKey": sortId,
            "transaction_hash": transaction_hash,
            "metadata": metadata,
            "expiresAt": expiresAt
        })

        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            logging.error(f"Error putting victim in DynamoDB: {response}")
        else:
            logging.info(f"Successfully put victim in DynamoDB: {response}")

    @staticmethod
    def read_entity_clusters(dynamo, address: str, chain_id) -> dict:
        entity_clusters = dict()
        itemId = f"{item_id_prefix}|{chain_id}|entity_cluster"
        sortKey = f"{address}"
        logging.debug(f"Reading entity clusters for address {address}, itemId {itemId}")
        logging.debug(f"Dynamo : {dynamo}")
        response = dynamo.query(KeyConditionExpression='itemId = :id AND sortKey = :sid',
                                ExpressionAttributeValues={
                                    ':id': itemId,
                                    ':sid': sortKey
                                }
                                )

        # Print retrieved item
        items = response.get('Items', [])
        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            entity_clusters[address] = item["cluster"]
        logging.info(f"Read entity clusters for address {address}. Retrieved {len(entity_clusters)} alert_clusters.")
        return entity_clusters

    @staticmethod
    def read_fp_mitigation_clusters(dynamo, chain_id) -> list:
        fp_mitigation_clusters = []        
        itemId = f"{item_id_prefix}|{chain_id}|fp_mitigation_cluster"
        logging.debug(f"Reading fp mitigation clusters, itemId {itemId}")
        logging.debug(f"Dynamo : {dynamo}")
        response = dynamo.query(KeyConditionExpression='itemId = :id',
                                ExpressionAttributeValues={
                                    ':id': itemId
                                }
                                )

        # Print retrieved item
        items = response.get('Items', [])
        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            fp_mitigation_clusters.append(item["address"])
        logging.info(f"Read fp mitigation clusters. Retrieved {len(fp_mitigation_clusters)} alert_clusters.")
        return fp_mitigation_clusters
    
    @staticmethod
    def read_end_user_attack_clusters(dynamo, chain_id) -> list:
        end_user_attack_clusters = []
        itemId = f"{item_id_prefix}|{chain_id}|end_user_attack_cluster"
        logging.debug(f"Reading end user attack clusters, itemId {itemId}")
        logging.debug(f"Dynamo : {dynamo}")
        response = dynamo.query(KeyConditionExpression='itemId = :id',
                                ExpressionAttributeValues={
                                    ':id': itemId,
                                }
                                )

        # Print retrieved item
        items = response.get('Items', [])
        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            end_user_attack_clusters.append(item["address"])
        logging.info(f"Read end user attack clusters. Retrieved {len(end_user_attack_clusters)} alert_clusters.")
        return end_user_attack_clusters
    
    @staticmethod
    def read_alert_data(dynamo, cluster: str, chain_id) -> pd.DataFrame:
        alert_data = pd.DataFrame()
        itemId = f"{item_id_prefix}|{chain_id}|alert"
        sortKey = f"{cluster}"
        logging.debug(f"Reading alert data for cluster {cluster}, itemId {itemId}, sortKey {sortKey}")
        logging.debug(f"Dynamo : {dynamo}")
        response = dynamo.query(KeyConditionExpression='itemId = :id AND sortKey = :sid',
                                ExpressionAttributeValues={
                                    ':id': itemId,
                                    ':sid': sortKey
                                }
                                )

        # Print retrieved item
        items = response.get('Items', [])
        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            dataframe_json = item["dataframe"]
            dataframe = pd.read_json(dataframe_json, orient="records")
            alert_data = pd.concat([alert_data, dataframe], ignore_index=True)
        logging.info(f"Read alert data for cluster {cluster}. Retrieved {len(alert_data)} alert_data.")
        return alert_data

    @staticmethod
    def delete_alert_data(dynamo, address, chain_id):
            itemId = f"{item_id_prefix}|{chain_id}|alert"
            sortKey = f"{address}"
            logging.debug(f"Deleting alert data for address {address}, itemId {itemId}, sortKey {sortKey}")
            logging.debug(f"Dynamo: {dynamo}")
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

    @staticmethod
    def read_victims(dynamo, chain_id) -> dict:
        victims = dict()
        itemId = f"{item_id_prefix}|{chain_id}|victim"
        logging.debug(f"Reading victims from shard, itemId {itemId}")
        logging.debug(f"Dynamo: {dynamo}")
        response = dynamo.query(
            KeyConditionExpression=Key('itemId').eq(itemId)
        )

        # Print retrieved items
        items = response.get('Items', [])
        logging.debug(f"Items retrieved: {len(items)}")
        for item in items:
            logging.debug(f"Item retrieved: {item}")
            victims[item["transaction_hash"]] = item["metadata"]
        logging.info(f"Read victims. Retrieved {len(victims)} victims.")
        return victims
    
    @staticmethod
    def clean_db(dynamo):
        item_types = ['entity_cluster', 'fp_mitigation_cluster', 'end_user_attack_cluster', 'alert', 'victim']
        chain_ids = [1, 10] # Only chains used in tests

        for chain_id in chain_ids:            
            for item_type in item_types:
                itemId = f"{item_id_prefix}|{chain_id}|{item_type}"
                lastEvaluatedKey = None
                while True:
                    if lastEvaluatedKey:
                        response = dynamo.query(
                            KeyConditionExpression=Key('itemId').eq(itemId),
                            ExclusiveStartKey=lastEvaluatedKey
                        )
                    else:
                        response = dynamo.query(
                            KeyConditionExpression=Key('itemId').eq(itemId)
                        )

                    items = response['Items']
                    for item in items:
                        dynamo.delete_item(Key={'itemId': item['itemId'], 'sortKey': item['sortKey']})
                        print("delete for " + item['itemId'])

                    if 'LastEvaluatedKey' in response:
                        lastEvaluatedKey = response['LastEvaluatedKey']
                    else:
                        break