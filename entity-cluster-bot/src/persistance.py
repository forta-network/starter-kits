import logging
import pickle
import sys
from datetime import datetime
import bz2
import networkx as nx
import time
import boto3
from boto3.dynamodb.conditions import Key
import random
import string


try:
    from src.constants import  GRAPH_KEY, DEV_DYNAMO_TABLE, S3_BUCKET, MUTEX_TIMEOUT_MILLIS, S3_REGION, DYNAMO_REGION, DYNAMODB_PRIMARY_KEY, DYNAMODB_SORT_KEY, BOT_ID
    from src.dyndbmutex import DynamoDbMutex
    from src.storage import get_secrets
except ModuleNotFoundError:
    from constants import  GRAPH_KEY, DEV_DYNAMO_TABLE, S3_BUCKET, MUTEX_TIMEOUT_MILLIS, S3_REGION, DYNAMO_REGION, DYNAMODB_PRIMARY_KEY, DYNAMODB_SORT_KEY, BOT_ID
    from dyndbmutex import DynamoDbMutex
    from storage import get_secrets


SECRETS_JSON = get_secrets()
AWS_ACCESS_KEY = SECRETS_JSON['aws']['accessKey']
AWS_SECRET_KEY = SECRETS_JSON['aws']['secretKey']


session = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=DYNAMO_REGION
)
dynamodb = session.resource('dynamodb')



s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name= S3_REGION
)

# {botId}|entity-cluster|{key}|{chainId}
PRIMARY_PREFIX = f"{BOT_ID}|entity-cluster"


class DynamoPersistance:
    name = None
    chain_id = None
    graph_cache = None
    table = None
    mutex:DynamoDbMutex = None


    def __init__(self, table = DEV_DYNAMO_TABLE, chain_id = 1):
        self.name = ''.join(random.choices(string.ascii_lowercase, k=5))
        self.chain_id = chain_id
        self.table = dynamodb.Table(table)
        self.mutex = DynamoDbMutex(f"mutex|{self.chain_id}", table, self.name, region_name=DYNAMO_REGION, ttl_minutes=15, timeoutms=MUTEX_TIMEOUT_MILLIS)
        print(f"chain id {self.chain_id}  - name {self.name} - dynamo table:  {table} ")
        self.graph_cache = self.load(GRAPH_KEY)
        if not self.graph_cache:
            self.graph_cache = nx.DiGraph()


    def persist(self, delta_graph: object, key: str, prune_graph):
        for n in range(5):
            locked = self.mutex.lock()
            if locked:
                try:
                    compose = []
                    shared_graph = self.load(GRAPH_KEY)
                    if shared_graph:
                        compose.append(shared_graph)
                    compose.append(delta_graph)
                    obj = nx.compose_all(compose)
                    prune_graph(obj)
                    bytes = pickle.dumps(obj)
                    size = self.bytes_to_kb(bytes)
                    c = bz2.compress(bytes)
                    c_size =  self.bytes_to_kb(c)
                    print(f"Persisting with MUTEX {key}/{self.chain_id} using API. Size:: {size} KB and compress {c_size} KB. {str(obj)}")
                    s3_key = f"{BOT_ID}/sub_graph/{self.chain_id}/{self.table.table_name}_SHARED_GRAPH"
                    s3.put_object(Body=c, Bucket=S3_BUCKET, Key=s3_key)
                    self.table.put_item(
                        Item={
                                DYNAMODB_PRIMARY_KEY: f"{PRIMARY_PREFIX}|{key}",
                                DYNAMODB_SORT_KEY: f"shared_graph|{self.chain_id}",
                                'updated': datetime.now().isoformat(),
                                'sizeKB': str(c_size), 
                                's3_key': s3_key
                            }
                        )
                    self.graph_cache = obj
                except Exception as e:
                    print(f"ERROR {e}")
                finally:
                    self.mutex.release()
                    break
            else:
                print(f"{self.name} table mutex is locked, tryinging in 2 second, try #{n}")
                time.sleep(2)

    def bytes_to_kb(self, bytes):
        size_in_bytes = sys.getsizeof(bytes)
        size_in_kb = size_in_bytes / 1024
        return size_in_kb     

    def load(self, key: str) -> object:
        logging.info(f"Loading {key}/{self.chain_id} using API")
        response = self.table.get_item(
            Key={
                DYNAMODB_PRIMARY_KEY: f"{PRIMARY_PREFIX}|{key}",
                DYNAMODB_SORT_KEY: f"shared_graph|{self.chain_id}"
            }
        )
        if "Item" in response:
            obj = s3.get_object(Bucket=S3_BUCKET, Key=response['Item']['s3_key'])
            compressed = obj['Body'].read()
            dc = bz2.decompress(compressed)
            return pickle.loads(dc)
        else:
            return None

    
    def clean_db(self) -> list:

        lastEvaluatedKey = None
        while True:
            if lastEvaluatedKey == None:
                response = self.table.query(
                    KeyConditionExpression=Key(DYNAMODB_PRIMARY_KEY).eq(f"{PRIMARY_PREFIX}|{GRAPH_KEY}")
                )
            else:
                response = self.table.query(
                    KeyConditionExpression=Key(DYNAMODB_PRIMARY_KEY).eq(f"{PRIMARY_PREFIX}|{GRAPH_KEY}"),
                    ExclusiveStartKey=lastEvaluatedKey
                )

            
            items = response['Items']
            for a_item in items:
                self.table.delete_item(Key={DYNAMODB_PRIMARY_KEY: a_item[DYNAMODB_PRIMARY_KEY], DYNAMODB_SORT_KEY: a_item[DYNAMODB_SORT_KEY]})
                print("delete for " + a_item[DYNAMODB_SORT_KEY])

            # Set our lastEvlauatedKey to the value for next operation,
            # else, there's no more results and we can exit
            if 'LastEvaluatedKey' in response:
                lastEvaluatedKey = response['LastEvaluatedKey']
            else:
                break

