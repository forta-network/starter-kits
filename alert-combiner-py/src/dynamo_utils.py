import logging
from datetime import datetime
import time
from src.constants import ALERTS_LOOKBACK_WINDOW_IN_HOURS
import pandas as pd
from src.utils import Utils 

item_id_prefix = ""

class DynamoUtils:
    @staticmethod
    def put_entity_cluster(dynamo, alert_created_at_str: str, address: str, cluster: str):
        global CHAIN_ID

        logging.debug(f"putting entity clustering alert for {address} in dynamo DB")
        alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        logging.debug(f"alert_created_at: {alert_created_at}")
        shard = Utils.get_shard(CHAIN_ID, alert_created_at)
        logging.debug(f"shard: {shard}")
        itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|entity_cluster|{address}"
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
    def put_fp_mitigation_cluster(dynamo, address: str):
        global CHAIN_ID

        logging.debug(f"putting fp mitigation cluster alert for {address} in dynamo DB")
        shard = Utils.get_shard(CHAIN_ID, time.time())
        logging.debug(f"shard: {shard}")
        itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|fp_mitigation_cluster|{address}"
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
    def put_end_user_attack_cluster(dynamo, address: str):
        global CHAIN_ID

        logging.debug(f"putting end user attack cluster alert for {address} in dynamo DB")
        shard = Utils.get_shard(CHAIN_ID, time.time())
        logging.debug(f"shard: {shard}")
        itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|end_user_attack_cluster|{address}"
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
    def put_alert_data(dynamo, cluster: str, dataframe: pd.DataFrame):
        global CHAIN_ID

        logging.debug(f"Putting alert data for cluster {cluster} in DynamoDB")
        alert_created_at = dataframe["created_at"].iloc[0] 
        logging.debug(f"alert_created_at: {alert_created_at}")
        shard = Utils.get_shard(CHAIN_ID, alert_created_at)
        logging.debug(f"shard: {shard}")
        itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|alert|{cluster}"
        logging.debug(f"itemId: {itemId}")
        sortId = f"{alert_created_at}"
        logging.debug(f"sortId: {sortId}")

        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60

        expiresAt = int(alert_created_at) + int(expiry_offset)
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
    def put_victim(dynamo, transaction_hash: str, metadata: dict):
        global CHAIN_ID

        logging.debug(f"Putting victim with transaction hash {transaction_hash} in DynamoDB")
        shard = Utils.get_shard(CHAIN_ID, time.time())
        logging.debug(f"shard: {shard}")
        itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|victim|{transaction_hash}"
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
    def read_entity_clusters(dynamo, address: str) -> dict:
        global CHAIN_ID

        entity_clusters = dict()
        for shard in range(Utils.get_total_shards(CHAIN_ID)):
            itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|entity_cluster|{address}"
            logging.debug(f"Reading entity clusters for address {address} from shard {shard}, itemId {itemId}")
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
                entity_clusters[address] = item["cluster"]
        logging.info(f"Read entity clusters for address {address}. Retrieved {len(entity_clusters)} alert_clusters.")
        return entity_clusters

    @staticmethod
    def read_fp_mitigation_clusters(dynamo, address: str) -> list:
        global CHAIN_ID

        fp_mitigation_clusters = []
        for shard in range(Utils.get_total_shards(CHAIN_ID)):
            itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|fp_mitigation_cluster|{address}"
            logging.debug(f"Reading fp mitigation clusters for address {address} from shard {shard}, itemId {itemId}")
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
        logging.info(f"Read fp mitigation clusters for address {address}. Retrieved {len(fp_mitigation_clusters)} alert_clusters.")
        return fp_mitigation_clusters
    
    @staticmethod
    def read_end_user_attack_clusters(dynamo, address: str) -> list:
        global CHAIN_ID

        end_user_attack_clusters = []
        for shard in range(Utils.get_total_shards(CHAIN_ID)):
            itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|end_user_attack_cluster|{address}"
            logging.debug(f"Reading end user attack clusters for address {address} from shard {shard}, itemId {itemId}")
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
                end_user_attack_clusters.append(item["address"])
        logging.info(f"Read end user attack clusters for address {address}. Retrieved {len(end_user_attack_clusters)} alert_clusters.")
        return end_user_attack_clusters
    
    @staticmethod
    def read_alert_data(dynamo, cluster: str) -> pd.DataFrame:
        global CHAIN_ID

        alert_data = pd.DataFrame()
        for shard in range(Utils.get_total_shards(CHAIN_ID)):
            itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|alert|{cluster}"
            logging.debug(f"Reading alert data for cluster {cluster} from shard {shard}, itemId {itemId}")
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
                dataframe_json = item["dataframe"]
                dataframe = pd.read_json(dataframe_json, orient="records")
                alert_data = pd.concat([alert_data, dataframe], ignore_index=True)
        logging.info(f"Read alert data for cluster {cluster}. Retrieved {len(alert_data)} alert_data.")
        return alert_data

    @staticmethod
    def delete_alert_data(dynamo, address):
        global CHAIN_ID

        for shard in range(Utils.get_total_shards(CHAIN_ID)):
            itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|alert|{address}"
            logging.debug(f"Deleting alert data for address {address} from shard {shard}, itemId {itemId}")
            logging.debug(f"Dynamo: {dynamo}")
            response = dynamo.delete_item(
                Key={
                    'itemId': itemId
                }
            )

            if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
                logging.error(f"Error deleting alert data for address {address} from DynamoDB: {response}")
            else:
                logging.info(f"Successfully deleted alert data for address {address} from DynamoDB")

    @staticmethod
    def read_victims(dynamo) -> dict:
        global CHAIN_ID

        victims = dict()
        for shard in range(Utils.get_total_shards(CHAIN_ID)):
            itemId = f"{item_id_prefix}|{CHAIN_ID}|{shard}|victim|"
            logging.debug(f"Reading victims from shard {shard}, itemId {itemId}")
            logging.debug(f"Dynamo: {dynamo}")
            response = dynamo.query(KeyConditionExpression='begins_with(itemId, :id)',
                                    ExpressionAttributeValues={
                                        ':id': itemId
                                    }
                                    )

            # Print retrieved items
            items = response.get('Items', [])
            logging.debug(f"Items retrieved: {len(items)}")
            for item in items:
                logging.debug(f"Item retrieved: {item}")
                victims[item["transaction_hash"]] = item["metadata"]
        logging.info(f"Read victims. Retrieved {len(victims)} victims.")
        return victims
