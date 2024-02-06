import forta_agent
import boto3
import json
import requests
import os

owner_db = "https://research.forta.network/database/owner/"
bucket_name = "prod-research-bot-data"
dynamo_table_name = "prod-research-bot-data"

test_mode = "main" if 'NODE_ENV' in os.environ and 'production' in os.environ.get('NODE_ENV') else "test"


def _token():
    tk = forta_agent.fetch_jwt({})
    return {"Authorization": f"Bearer {tk}"}


def _load_json(key: str) -> object:
    if test_mode == "test":
        # loading json from local file secrets.json
        with open("secrets.json") as f:
            return json.load(f)
    else:
        res = requests.get(f"{owner_db}{key}", headers=_token())
        if res.status_code == 200:
            return res.json()
        else:
            raise f"error loading {key}"


def get_secrets():
    return _load_json("secrets.json")


# Returns a boto3 s3 client
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#client
def s3_client(secrets, region='us-east-1'):
    return boto3.client('s3',
                        aws_access_key_id=secrets['aws']['accessKey'],
                        aws_secret_access_key=secrets['aws']['secretKey'],
                        region_name=region)


# Returns a boto3 table resource
# All Items must have two string properties:  itemId, sortKey
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/table/index.html
def dynamo_table(secrets, region='us-east-1'):
    d = boto3.resource('dynamodb',
                       aws_access_key_id=secrets['aws']['accessKey'],
                       aws_secret_access_key=secrets['aws']['secretKey'],
                       region_name=region)

    return d.Table(dynamo_table_name)
