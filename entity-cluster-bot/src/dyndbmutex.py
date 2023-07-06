import logging
import boto3
import botocore
import datetime
import uuid
import os
from boto3.dynamodb.conditions import Attr

try:
    from src.storage import get_secrets
    from src.constants import  DYNAMODB_PRIMARY_KEY, DYNAMODB_SORT_KEY, DYNAMODB_TTL_KEY
except ModuleNotFoundError:
    from constants import  DYNAMODB_PRIMARY_KEY,DYNAMODB_SORT_KEY, DYNAMODB_TTL_KEY
    from storage import get_secrets

SECRETS_JSON = get_secrets()
AWS_ACCESS_KEY = SECRETS_JSON['aws']['ACCESS_KEY']
AWS_SECRET_KEY = SECRETS_JSON['aws']['SECRET_KEY']
BOT_ID = SECRETS_JSON['botId']
PRIMARY = f"{BOT_ID}|entity-cluster|mutex"



logger = logging.getLogger('dyndbmutex')

def setup_logging():
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s %(asctime)s - %(name)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


NO_HOLDER = '__empty__'
TWO_DAYS_IN_MINUTES = 2*24*60

class AcquireLockFailedError(Exception):
        pass


def timestamp_millis():
    return int((datetime.datetime.utcnow() -
                datetime.datetime(1970, 1, 1)).total_seconds() * 1000)


class MutexTable:

    def __init__(self, table_name, region_name='us-west-2', ttl_minutes=TWO_DAYS_IN_MINUTES):
        self.dbresource = boto3.resource('dynamodb', region_name=region_name, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
        self.table_name = table_name
        logger.info("Mutex table name is " + self.table_name)
        self.ttl_minutes = ttl_minutes
        self.get_table()

    def get_table(self):
        return self.dbresource.Table(self.table_name)

    def get_lock(self, lockname):
        return self.get_table().get_item(Key={DYNAMODB_PRIMARY_KEY: PRIMARY, DYNAMODB_SORT_KEY: lockname})


    def write_lock_item(self, lockname, caller, waitms):
        expire_ts = timestamp_millis() + waitms
        ttl = expire_ts//1000 + self.ttl_minutes*60
        logger.debug("Write_item: lockname=" + lockname + ", caller=" +
                     caller + ", Expire time is " + str(expire_ts))
        try:
            self.get_table().put_item(
                Item={
                    DYNAMODB_PRIMARY_KEY: PRIMARY,
                    DYNAMODB_SORT_KEY: lockname,
                    'expire_ts': expire_ts,
                    'holder': caller,
                    DYNAMODB_TTL_KEY: ttl
                },
                # TODO: adding Attr("holder").eq(caller) should make it re-entrant
                ConditionExpression=Attr("holder").eq(NO_HOLDER) | Attr(DYNAMODB_PRIMARY_KEY).not_exists()
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
                    DYNAMODB_PRIMARY_KEY: PRIMARY,
                    DYNAMODB_SORT_KEY: lockname,
                    'expire_ts': 0,
                    'holder': NO_HOLDER
                },
                ConditionExpression=Attr("holder").eq(caller) | Attr(DYNAMODB_PRIMARY_KEY).not_exists()
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
                    DYNAMODB_PRIMARY_KEY: PRIMARY,
                    DYNAMODB_SORT_KEY: lockname,
                    'expire_ts': 0,
                    'holder': NO_HOLDER
                },
                ConditionExpression=Attr("expire_ts").lt(now) | Attr(DYNAMODB_PRIMARY_KEY).not_exists()
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                logger.info("Prune: lockname=" + lockname + ", caller=" + caller +
                             " Prune failed")
                return False
        logger.debug("Prune: lockname=" + lockname + ", caller=" + caller + " Prune succeeded")
        return True


class DynamoDbMutex:

    def __init__(self, name, table_name, holder=None,
                 timeoutms=10 * 1000, region_name='us-west-2', ttl_minutes=TWO_DAYS_IN_MINUTES):
        if holder is None:
            holder = str(uuid.uuid4())
        self.lockname = name
        self.holder = holder
        self.timeoutms = timeoutms
        self.table = MutexTable(table_name, region_name=region_name, ttl_minutes=ttl_minutes)
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
