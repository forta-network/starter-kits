import logging
import boto3
import botocore
import datetime
import uuid
import os
from boto3.dynamodb.conditions import Attr

try:
    from src.storage import get_secrets
    from src.constants import  DYNAMO_MUTEX_TABLE_NAME
except ModuleNotFoundError:
    from constants import  DYNAMO_MUTEX_TABLE_NAME
    from storage import get_secrets

SECRETS_JSON = get_secrets()
AWS_ACCESS_KEY = SECRETS_JSON['aws']['ACCESS_KEY']
AWS_SECRET_KEY = SECRETS_JSON['aws']['SECRET_KEY']


logger = logging.getLogger('dyndbmutex')

def setup_logging():
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s %(asctime)s - %(name)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


DEFAULT_MUTEX_TABLE_NAME = DYNAMO_MUTEX_TABLE_NAME
NO_HOLDER = '__empty__'
TWO_DAYS_IN_MINUTES = 2*24*60

class AcquireLockFailedError(Exception):
        pass


def timestamp_millis():
    return int((datetime.datetime.utcnow() -
                datetime.datetime(1970, 1, 1)).total_seconds() * 1000)


class MutexTable:

    def __init__(self, region_name='us-west-2', ttl_minutes=TWO_DAYS_IN_MINUTES):
        endpoint_url = os.environ.get("DYNAMO_DB_URL", None)
        self.dbresource = boto3.resource('dynamodb', region_name=region_name, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
        self.dbclient = boto3.client('dynamodb', region_name=region_name, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
        self.table_name = os.environ.get('DD_MUTEX_TABLE_NAME', DEFAULT_MUTEX_TABLE_NAME)
        logger.info("Mutex table name is " + self.table_name)
        self.ttl_minutes = ttl_minutes
        self.get_table()

    def get_table(self):
        try:
            self.dbclient.describe_table(TableName=self.table_name)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return self.create_table()
            else:
                raise
        else:
            return self.dbresource.Table(self.table_name)

    def delete_table(self):
        self.dbclient.delete_table(TableName=self.table_name)
        logger.info("Deleted table " + self.table_name)

    def get_lock(self, lockname):
        return self.get_table().get_item(Key={'lockname': lockname})

    def create_table(self):
        try:
            table = self.dbresource.create_table(
                TableName=self.table_name,
                KeySchema=[
                    {
                        'AttributeName': 'lockname',
                        'KeyType': 'HASH'  # Partition key
                    },
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'lockname',
                        'AttributeType': 'S'
                    },
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 2,
                    'WriteCapacityUnits': 2
                }
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceInUseException':
                logger.debug("Table already exists", exc_info=e)
            else:
                raise
        else:
            logger.debug("Called create_table")
            table.wait_until_exists()
            logger.info("Created table " + self.table_name)
            try:
                self.dbclient.update_time_to_live(
                TableName=self.table_name,
                TimeToLiveSpecification={
                 'Enabled': True,
                 'AttributeName': 'ttl'
                })
            except botocore.exceptions.ClientError as e:
                logger.error("Error setting TTL on table", exc_info=e)
            return table

    def write_lock_item(self, lockname, caller, waitms):
        expire_ts = timestamp_millis() + waitms
        ttl = expire_ts//1000 + self.ttl_minutes*60
        logger.debug("Write_item: lockname=" + lockname + ", caller=" +
                     caller + ", Expire time is " + str(expire_ts))
        try:
            self.get_table().put_item(
                Item={
                    'lockname': lockname,
                    'expire_ts': expire_ts,
                    'holder': caller,
                    'ttl': ttl
                },
                # TODO: adding Attr("holder").eq(caller) should make it re-entrant
                ConditionExpression=Attr("holder").eq(NO_HOLDER) | Attr('lockname').not_exists()
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.info("Write_item: lockname=" + lockname +
                             ", caller=" + caller + ", lock is being held")
                return False
        logger.debug("Write_item: lockname=" + lockname +
                     ", caller=" + caller + ", lock is acquired")
        return True

    def clear_lock_item(self, lockname, caller):
        try:
            self.get_table().put_item(
                Item={
                    'lockname': lockname,
                    'expire_ts': 0,
                    'holder': NO_HOLDER
                },
                ConditionExpression=Attr("holder").eq(caller) | Attr('lockname').not_exists()
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.warning("clear_lock_item: lockname=" + lockname + ", caller=" + caller +
                             " release failed")
                return False
        logger.debug("clear_lock_item: lockname=" + lockname + ", caller=" + caller + " release succeeded")
        return True

    def prune_expired(self, lockname, caller):
        now = timestamp_millis()
        logger.debug("Prune: lockname=" + lockname + ", caller=" + caller +
                     ", Time now is %s" + str(now))
        try:
            self.get_table().put_item(
                Item={
                    'lockname': lockname,
                    'expire_ts': 0,
                    'holder': NO_HOLDER
                },
                ConditionExpression=Attr("expire_ts").lt(now) | Attr('lockname').not_exists()
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.info("Prune: lockname=" + lockname + ", caller=" + caller +
                             " Prune failed")
                return False
        logger.debug("Prune: lockname=" + lockname + ", caller=" + caller + " Prune succeeded")
        return True


class DynamoDbMutex:

    def __init__(self, name, holder=None,
                 timeoutms=10 * 1000, region_name='us-west-2', ttl_minutes=TWO_DAYS_IN_MINUTES):
        if holder is None:
            holder = str(uuid.uuid4())
        self.lockname = name
        self.holder = holder
        self.timeoutms = timeoutms
        self.table = MutexTable(region_name=region_name, ttl_minutes=ttl_minutes)
        self.locked = False

    def lock(self):
        self.table.prune_expired(self.lockname, self.holder)
        self.locked = self.table.write_lock_item(self.lockname, self.holder, self.timeoutms)
        logger.info("mutex.lock(): lockname=" + self.lockname + ", locked = " + str(self.locked))
        return self.locked

    def release(self):
        released = self.table.clear_lock_item(self.lockname, self.holder)
        self.locked = not released
        logger.info("mutex.release(): lockname=" + self.lockname + ", locked = " + str(self.locked))

    def __enter__(self):
        locked = self.lock()
        if not locked:
            raise AcquireLockFailedError()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()

    def is_locked(self):
        return self.locked

    def get_raw_lock(self):
        return self.table.get_lock(self.lockname)

    @staticmethod
    def delete_table(region_name='us-west-2'):
        table = MutexTable(region_name)
        table.delete_table()