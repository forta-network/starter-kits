from unittest.mock import Mock
from datetime import datetime
import time
import pandas as pd
import hashlib

from dynamo_utils import DynamoUtils, TEST_TAG
from constants import ALERTS_LOOKBACK_WINDOW_IN_HOURS, FP_MITIGATION_EXPIRY_IN_HOURS, FUNDING_STAGE_ALERTS_LOOKBACK_WINDOW_IN_HOURS


class TestDynamoUtils:
    CHAIN_ID = 1

    def test_put_entity_cluster(self):
        dynamo = Mock()
        dynamo.put_item.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}}
        address = '0x123456789'
        cluster = 'entity_cluster'
        alert_created_at_str = '2022-01-01T00:00:00'
        alert_created_at = datetime.strptime(alert_created_at_str[0:19], "%Y-%m-%dT%H:%M:%S").timestamp()

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID)
        expiresAt = du._get_expires_at(alert_created_at)

        du.put_entity_cluster(dynamo, alert_created_at_str, address, cluster)

        sortIdHash = hashlib.sha256(address.encode()).hexdigest()

        dynamo.put_item.assert_called_once_with(Item={'itemId': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|entity_cluster',
                                                'sortKey': sortIdHash, 'address': address, 'cluster': cluster, 'expiresAt': expiresAt})

    def test_put_fp_mitigation_cluster(self):
        dynamo = Mock()
        dynamo.put_item.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}}
        address = '0x123456789'
        expiry_offset = FP_MITIGATION_EXPIRY_IN_HOURS * 60 * 60
        expiresAt = int(time.time()) + int(expiry_offset)

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID) 
        du.put_fp_mitigation_cluster(dynamo, address) 

        sortIdHash = hashlib.sha256(address.encode()).hexdigest()

        dynamo.put_item.assert_called_once_with(
            Item={'itemId': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|fp_mitigation_cluster', 'sortKey': sortIdHash, 'address': address, 'expiresAt': expiresAt})

    def test_put_end_user_attack_cluster(self):
        dynamo = Mock()
        dynamo.put_item.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}}
        address = '0x123456789'
        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60
        expiresAt = int(time.time()) + int(expiry_offset)

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID) 
        du.put_end_user_attack_cluster(dynamo, address)

        sortIdHash = hashlib.sha256(address.encode()).hexdigest()

        dynamo.put_item.assert_called_once_with(
            Item={'itemId': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|end_user_attack_cluster', 'sortKey': sortIdHash, 'address': address, 'expiresAt': expiresAt})
    
    def test_put_alert_data(self):
        dynamo = Mock()
        dynamo.put_item.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}}
        cluster = 'alert_cluster'
        dataframe = pd.DataFrame(
            {'created_at': ['2022-01-01T00:00:00'], 'data': ['test'], 'stage': 'Exploitation'})
        dataframe['created_at'] = pd.to_datetime(dataframe['created_at'])
        first_alert_created_at_str = dataframe['created_at'].iloc[0]
        first_alert_created_at = first_alert_created_at_str.timestamp()
        dataframe_json = dataframe.to_json(orient="records")
        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60
        expiresAt = int(first_alert_created_at) + int(expiry_offset)

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID) 
        du.put_alert_data(dynamo, cluster, dataframe, "Exploitation")

        sortIdHash = hashlib.sha256(cluster.encode()).hexdigest()

        dynamo.put_item.assert_called_once_with(Item={'itemId': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|alert',
                                                'sortKey': sortIdHash, 'cluster': cluster, 'dataframe': dataframe_json, 'expiresAt': expiresAt})
        
    def test_put_alert_data_funding_stage(self):
        dynamo = Mock()
        dynamo.put_item.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}}
        cluster = 'alert_cluster'
        dataframe = pd.DataFrame(
            {'created_at': ['2022-01-01T00:00:00'], 'data': ['test'], 'stage': 'Funding'})
        dataframe['created_at'] = pd.to_datetime(dataframe['created_at'])
        first_alert_created_at_str = dataframe['created_at'].iloc[0]
        first_alert_created_at = first_alert_created_at_str.timestamp()
        dataframe_json = dataframe.to_json(orient="records")
        expiry_offset = FUNDING_STAGE_ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60
        expiresAt = int(first_alert_created_at) + int(expiry_offset)

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID) 
        du.put_alert_data(dynamo, cluster, dataframe, "Funding")

        sortIdHash = hashlib.sha256(cluster.encode()).hexdigest()

        dynamo.put_item.assert_called_once_with(Item={'itemId': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|alert',
                                                'sortKey': sortIdHash, 'cluster': cluster, 'dataframe': dataframe_json, 'expiresAt': expiresAt})
    
    def test_put_victim(self):
        dynamo = Mock()
        dynamo.put_item.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}}
        transaction_hash = '0xabcdef123456'
        metadata = {'key': 'value'}
        expiry_offset = ALERTS_LOOKBACK_WINDOW_IN_HOURS * 60 * 60
        expiresAt = int(time.time()) + int(expiry_offset)

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID) 
        du.put_victim(dynamo, transaction_hash, metadata)

        sortIdHash = hashlib.sha256(transaction_hash.encode()).hexdigest()
        dynamo.put_item.assert_called_once_with(Item={'itemId': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|victim',
                                                'sortKey': sortIdHash, 'transaction_hash': transaction_hash, 'metadata': metadata, 'expiresAt': expiresAt})

    def test_read_entity_clusters(self):
        dynamo = Mock()
        address = '0x123456789'
        items = [{'cluster': 'cluster1'},
                 {'cluster': 'cluster2'}]
        response = {'Items': items}
        dynamo.query.return_value = response

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID)
        du.read_entity_clusters(dynamo, address)

        sortIdHash = hashlib.sha256(address.encode()).hexdigest()

        dynamo.query.assert_called_once_with(KeyConditionExpression='itemId = :id AND sortKey = :sid', ExpressionAttributeValues={
                                         ':id': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|entity_cluster', ':sid': f'{sortIdHash}'})

    def test_read_fp_mitigation_clusters(self):
        dynamo = Mock()
        items = [{'address': '0x123456789', 'expiresAt': 1641074400}]
        response = {'Items': items}
        dynamo.query.return_value = response

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID)
        du.read_fp_mitigation_clusters(dynamo)

        dynamo.query.assert_called_once_with(KeyConditionExpression='itemId = :id', ExpressionAttributeValues={
            ':id': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|fp_mitigation_cluster'})

    def test_read_end_user_attack_clusters(self):
        dynamo = Mock()
        items = [{'address': '0x123456789', 'expiresAt': 1641074400}]
        response = {'Items': items}
        dynamo.query.return_value = response

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID)
        du.read_end_user_attack_clusters(dynamo)

        dynamo.query.assert_called_once_with(KeyConditionExpression='itemId = :id', ExpressionAttributeValues={
            ':id': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|end_user_attack_cluster'})

    def test_read_alert_data(self):
        dynamo = Mock()
        cluster = 'alert_cluster'
        items = [{'cluster': 'alert_cluster', 'sortKey': '1641074400',
                  'dataframe': '{"created_at":{"0":"2022-01-01T00:00:00"},"data":{"0":"test"}}'}]
        response = {'Items': items}
        dynamo.query.return_value = response

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID)
        du.read_alert_data(dynamo, cluster)

        sortIdHash = hashlib.sha256(cluster.encode()).hexdigest()

        dynamo.query.assert_called_once_with(KeyConditionExpression='itemId = :id AND sortKey = :sid', ExpressionAttributeValues={
            ':id': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|alert', ':sid': f'{sortIdHash}'})

    def test_read_victims(self):
        dynamo = Mock()
        items = [{'transaction_hash': '0xabcdef123456', 'sortKey': '1641074400',
                'metadata': '{"key":"value"}'}]
        response = {'Items': items}
        dynamo.query.return_value = response

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID)
        du.read_victims(dynamo)

        dynamo.query.assert_called_once_with(
            KeyConditionExpression='itemId = :id',
            ExpressionAttributeValues={
                ':id': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|victim'
            }
        )

    def test_delete_alert_data(self):
        dynamo = Mock()
        address = '0x432423'
        dynamo.delete_item.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200}}

        du = DynamoUtils(TEST_TAG, TestDynamoUtils.CHAIN_ID)
        du.delete_alert_data(dynamo, address)
        dynamo.delete_item.assert_called_once_with(
            Key={'itemId': f'{du.tag}|{TestDynamoUtils.CHAIN_ID}|alert',
                 'sortKey': f'{address}'}
        )
