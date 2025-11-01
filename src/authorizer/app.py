import json
import jwt
from botocore.exceptions import ClientError
import os
import time

SECRET_KEY = os.environ.get("SECRET_KEY","54353245345234534535tdfasdfadsfsdf2243252454t43adaf")

def authorizer(event, context):
    token = event['headers']['Authorization']
    if token.startswith("Bearer "):
        token = token.split(" ")[1]
    
    try:
        print(token)
        print(event)
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        print("Token exp:", decoded.get("exp"))
        print("Now:", int(time.time()))
        principal_id = decoded['email']
        custom_context = {
            
            'role': decoded.get('role', 'guest')
        }
        policy = generate_policy(principal_id, 'Allow', event['methodArn'],custom_context)
        print(policy)
        return policy
    except jwt.ExpiredSignatureError:
        policy = generate_policy('', 'Deny', event['methodArn'],{})
        print("Expired token")
        print(policy)
        return policy # Token has expired
    except jwt.InvalidTokenError:   
        policy = generate_policy('', 'Deny', event['methodArn'],{})
        print("Invalid token")
        print(policy)
        return policy # Token has expired  # Invalid token

def generate_policy(principal_id, effect, resource,context):
    policy = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': resource
                }
            ]
        },
        'context':context
    
    }
    return policy
