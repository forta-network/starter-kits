# Entity Cluster Bot

## Description

This agent detects whether two or more accounts are likely controlled by the same entity through simple heuristics. The purpose of this bot is for downstream consumption, for example, to propagate alerts across multiple accounts.

It operates under the assumption that sending of tokens/ ETH for newer accounts is likely controlled by the same entity. The following heuristics are applied:
- bidirectional funding
- large fund transfers to EOAs
- fund of two completely new accounts (e.g. 0x14c19962e4a899f29b3dd9ff52ebfb5e4cb9a067)
Further, contracts created by an address are also considered part of the same entity.

The bot generates a graph and identifies and reports on the connected components.

A entity is created if this condition is observed accounts with less than MAX_NONCE transactions. Entities will age out within MAX_AGE_IN_DAYS.


## Sharding Implementation Details
The bot has a graph of the connections between the addresses that must be shared between many intances. All instances read and write the shared graph at the same time, so to avoid race condition it use a 
mutex implemented in dynamodb using  [DynamoDb conditional write](http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithItems.html#WorkingWithItems.ConditionalUpdate) and [atomic compare-and-swap](https://en.wikipedia.org/wiki/Compare-and-swap) 

Also we store the graph in s3 as the graph compressed can be around 15MB and optimize costs

Each instance updates the shared graoh every TX_SAVE_STEP 



## Infrastructure

The bot needs 1 dynamo table and 1 s3 bucket.  the dynamodb and the s3 can be in different region, so is better to look for the cheapest regions at the moment before deploy.

### DYNAMO_TABLE= "prod-research-bot-data"
It store the metadata of the shared graph and also manage the mutex (There is one registry per chain, 7 at the moment)
The mutex also has a expire time of 10s at application level and a dynamo ttl at infrastructure level to avoid the mutex being lock if an intance is shutdown in the forta network. 
The Mutex only use dynamo write capacity

#### set up a dynamo db on AWS
1. create table
table name : your-table-name
Table class: DynamoDB standard
Partition Key: itemId(String)
Sort Key: sortKey(String)
Customize settings
DynamoDB standard
Read capacity : minimum 2
Write capacity : minimum 2
leave the rest as default
Create table 

2. Set up the ttl:
ttl feature: on
ttl name field: expiresAt

place the instance in the same region as the s3 bucket 

### S3_BUCKET= "prod-research-bot-data"
S3 bucket to store the shared graph, one chared graph per chain.

1. create a S3 bucket
bucket name: your-bucket-name
Leave the rest as default
creatre bucket

### Set up IAM permission

#### Create a policy for the bot
1. go to IAM
2. go to policies
3. create policy
4. go to JSON tab
5. paste the following policy
6. replace the bucket name and the table name with the ones you created (S3_ARN and TABLE_ARN) ARN(Amazon Ressource Name) can be found in the bucket and table details. 
7. click on next
8. Set up the name of the policy
9. click on create policy


Keep them as low as possible, here a template:

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "dynamodb:PutItem",
                "dynamodb:DescribeTable",
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:Scan",
                "dynamodb:Query",
                "dynamodb:UpdateItem"
            ],
            "Resource": "TABLE_ARN"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject"
            ],
            "Resource": "S3_ARN"
        }
    ]
}

#### Assign permission to a user 
1. go to IAM
2. go to users
3. create or select a user
4. go to permissions tab
5. click on add permission
6. click on attach existing policies directly
7. search for the policy you created
8. click on next
9. click on add permission


#### Get the credentials
1. go to IAM
2. go to users
3. select a user
4. go to security credentials tab
5. click on create access key
6. click on show
7. copy the access key and the secret key
8. paste them in the secret.json file


### Infrastructure cost
Each instance updates the graph every TX_SAVE_STEP, asking for the mutex, saving metadata, reading from s3,  writing in s3 and releasing the mutex all these operations cost $$$. The lower the TX_SAVE_STEP, the more accurate the alert are as the 
instances "knows what is hapening in the other" but there are more operation over the infrastructure so the cost are higher. By design there is a relationship betweeen cost and accuracy. 


## Credentials configuration
Credential should be in secret.json, a template to start could be:

{   
    "apiKeys": {
      "ZETTABLOCK": ""
    },
    "aws": {
      "ACCESS_KEY": "",
      "SECRET_KEY": ""
    },
}

ZETTABLOCK for alert stats
AWS.* infrastructure

### constants.py
you may have to change the constants.py file to match your infrastructure, zone and ressource names.


## RPC Timeout
Web3 RPC call are time consuming, there is now a HTTP_RPC_TIMEOUT=2 config to avoid waiting to long if we hit a slow server from the provider. If the rpc call doesn't finish in 2 second it will raise a exception and will continue with the next transaction. usually a rpc call should be 500ms


## Supported Chains

- All Forta Supported Chains

## Alerts

- ENTITY-CLUSTER
  - Fired when a new entity with more than one address is detected
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata will contain a unique entity identifier along with all the addresses that are currently associated with the entity. Also it will have the diagram so can be processed online via d3.js or similar

## Test Data

Ronin Bridge exploiter

npm run tx 0x431136dd361557abe34fe4685a278654e9e1bc7547a40719b348c096c5092d2b,0x5dfb733a9522f72e4dff5d6cb635135ee599cf3c19f2b9e4a8c91fba7e7aeb45

creates entity with 0x098b716b8aaf21512996dc57eb0615e2383e2f96 and 0xe708f17240732bbfa1baa8513f66b665fbc7ce10

DFX Finance Exploiter
npm run tx 0xc8268a45d0043875d8d2eb953b25fbaf3de5fb00f7f9aea0597bc9d5138df0cf,0x5d029c08f5c283716f9fe962218f8429c7ca0b2eb50dda4062b33dbdf74314f6


## Experimental
There is a entity graph viewer that get the metadata of an alert and extract the graph diagram for alerts between 8 and 16 entities

..entity-cluster-bot/viewer/index.html?alertId=0x1d9d84ab28c3c507885329630269326094262c998d9292fb8bef95eb3748c7f4



