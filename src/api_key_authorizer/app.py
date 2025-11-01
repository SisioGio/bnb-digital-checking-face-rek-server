import boto3
import os

dynamodb = boto3.resource('dynamodb')


TABLE_NAME = os.environ.get('HOST_TABLE_NAME','restaurant-crm-RestaurantsTable-XHVLN058UT37')
restaurants = dynamodb.Table(TABLE_NAME)
def lambda_handler(event, context):
    api_key = event['headers'].get('x-api-key')
    if not api_key:
        return _deny('Unauthorized: Missing API key')

    # Look up user by API key using GSI
    response = restaurants.query(
        TableName=TABLE_NAME,
        IndexName='api_key-index',
        KeyConditionExpression='api_key = :k',
        ExpressionAttributeValues={':k':  api_key},
        Limit=1
    )

    if not response['Items']:
        return _deny('Unauthorized: Invalid API key')

    # Optional: You can extract user_id or roles here
    user = response['Items'][0]

    restaurant_id = user['restaurant_id']

    return _allow(restaurant_id, event['methodArn'])


def _allow(principal_id, resource):
    return {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": resource
            }]
        }
    }

def _deny(msg):
    return {
        "principalId": "unauthorized",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": "Deny",
                "Resource": "*"
            }]
        },
        "context": {
            "error": msg
        }
    }
