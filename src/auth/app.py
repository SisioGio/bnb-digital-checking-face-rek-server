import json
import os
import boto3
from botocore.exceptions import ClientError
import bcrypt
import jwt
import time
import random
import string

from datetime import datetime, timedelta
import secrets

ses_client = boto3.client('ses')
dynamodb = boto3.resource('dynamodb')


SECRET_KEY = os.environ.get("SECRET_KEY","54353245345234534535tdfasdfadsfsdf2243252454t43adaf")
REFRESH_SECRET_KEY= os.environ.get('REFRESH_SECRET_KEY',"FSDNFJSANDFAJSDFURY34R5349856FDUNIDNSIFUHASFOIUSADFUIASYG!!!!\DF;DSF]S[GSG\DFG'D\FG]")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "https://www.airbnb.finbotix.de/")
JWT_EXPIRATION = int(os.environ.get('JWT_EXPIRATION', int(3600)))
ACCESS_TOKEN_EXPIRATION = int(os.environ.get('ACCESS_TOKEN_EXPIRATION',int(60*60*24*14)))


USERS_TABLE = os.getenv("USERS_TABLE",'airbnb-template-UsersTable-FJ2YQX72G0AK')

table = dynamodb.Table(USERS_TABLE)

ses_client = boto3.client('ses')
dynamodb = boto3.resource('dynamodb')



def lambda_handler(event, context):
    # Determine the HTTP method
    method = event.get("httpMethod")

    if method == 'POST' and event['path'] == '/auth/register':
        return register_user(event)
    if method == 'POST' and event['path'] == '/auth/login':
        return login_user(event)
    if method == 'POST' and event['path'] == '/auth/confirm':
        return verify_account(event)
    if method == 'GET' and event['path'] == '/auth/confirm':
        return send_confirmation_email(event)
    if method == 'POST' and event['path'] == '/auth/refresh':
        return refresh_access_token(event)
    if method == 'POST' and event['path'] == '/auth/request-password-reset':
        return request_password_reset(event)
    if method == 'POST' and event['path'] == '/auth/reset-password':
        return reset_password(event)
    else:
        return generate_response(400,{"msg":'Invalid route or method.','event':event})

def generate_response(statusCode,message):
    return {
        'statusCode': statusCode,
        'headers': {
                            'Access-Control-Allow-Headers': 'Content-Type',
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
                        },
        'body': json.dumps(message)
    }




def request_password_reset(event):
    try:
        # Get the email from the request body
        body = json.loads(event.get('body'))
        email = body.get('email')
        print("Generating email for passwor reset")
        if not email:
            return generate_response(400, {'message': 'Email is required'})
        # Generate a password reset token (JWT)
        reset_token = generate_jwt(email,'password-reset')


        reset_url = f"{FRONTEND_BASE_URL}/reset-password?token={reset_token}"

        subject = "🔑 Reset Your Password and Regain Access to Your Account"
        body = PASSWORD_RESET_TEMPLATE.replace("{{reset_url}}", reset_url)
        send_email(email, subject, body)
        return generate_response(200, {'message': 'Password reset email sent successfully','token':reset_token})
        
    except Exception as e:
        return generate_response(500, {'message': f'Error: {str(e)}'})
        

def reset_password(event):
    try:
        body = json.loads(event.get('body'))
        token = body.get('token')
        new_password = body.get('newPassword')

        # Validate token (decode JWT token)
        payload = verify_jwt(token)
        print(payload)
        if 'error' in payload:
            return generate_response(400, {'message': 'Invalid or expired token'})
            
        # Extract email from the token payload
        email = payload['email']



        # Update password in the database
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        response = table.update_item(
            Key={"email": email},
            UpdateExpression="SET password = :val",
            ExpressionAttributeValues={":val": hashed_password.decode("utf-8")},
            ReturnValues="UPDATED_NEW"
        )
        return generate_response(200, {'message': 'Password reset successfully'})
        
    except Exception as e:
        return generate_response(500, {'message': f'Error: {str(e)}'})
        
def verify_jwt(token: str) -> dict:
    """Verify JWT and return payload."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}


def verify_account(event):
    try:
        body = json.loads(event.get('body', '{}'))
        token = body.get('token', '')
        # Verify JWT
        payload = verify_jwt(token)
        
        if "error" in payload:
            return generate_response(400, {'message': 'Invalid or expired token'})
            
        
        email = payload["email"]
        
        # Update DynamoDB to set 'verified' to True
        
        response = table.update_item(
            Key={"email": email},
            UpdateExpression="SET verified = :val",
            ExpressionAttributeValues={":val": True},
            ReturnValues="UPDATED_NEW"
        )
        return generate_response(200, {'message': 'Account verified successfully'})
        
    except Exception as e:
        return generate_response(500, {'message': f'Error: {str(e)}'})
        

def generate_jwt(email: str, mode: str) -> str:
    """Generate a JWT for either 'confirm' or 'reset' mode."""
    payload = {
        "email": email,
        "mode": mode,
        "exp": datetime.utcnow() + timedelta(seconds=int(JWT_EXPIRATION))
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def send_email(recipient, subject, body):
    
    try:
        # """Send email via SES."""
        response = ses_client.send_email(
            Source= os.environ.get('SES_SENDER_EMAIL','notification@airbnb.finbotix.de'),
            Destination={'ToAddresses': [recipient]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Html': {'Data': body}}
            }
        )
        return response
    except Exception as e:
        print(e)
        return False
    

def generate_url(email: str, mode: str) -> str:
    """Generate URL with JWT for frontend."""
    token = generate_jwt(email, mode)
    path = "confirm" if mode == "confirm" else "reset"
    url = f"{FRONTEND_BASE_URL}/{path}?token={token}"
    return url

def send_confirmation_email(event):
    try:
        
        
        email = event['queryStringParameters']['email']
       
        # Check if user exists
        user = get_user_by_email(email)

        if not user:
            return generate_response(404, {'message': 'User not found'})
           
        
        confirmation_url = generate_url(email, "confirm")
        subject = "You're Almost There! Confirm Your Registration for Agents4People"
        body = ACCOUNT_CONFIRMATION_TEMPLATE.replace("{{confirmation_url}}", confirmation_url)
        send_email(email, subject, body)
        print(confirmation_url)
        return generate_response(200, {'message': 'Confirmation email sent successfully'})
        
    except Exception as e:
        return generate_response(500, {'message': f'Error: {str(e)}'})
        





def login_user(event):
    try:
        body = json.loads(event.get('body','{}'))
        password = body.get('password','')
        email=body.get('email','')

        # Check if user exists
        user = get_user_by_email(email)

        if not user:
            return generate_response(404, {'message': 'User not found'})
            

        password_is_correct = bcrypt.checkpw(password.encode('utf-8'),user['password'].encode('utf-8'))

        if not password_is_correct:
            print(password_is_correct)
            return generate_response(403, {'message': 'Invalid password'})

        api_key = user.get('api_key', None)

        # Generate JWT access token
        payload = {
           
            'email': user.get('email'),
            'api_key': api_key,
            'name':user.get('name','N/A'),
            'verified': user.get('verified',False),
            'last_name':user.get('last_name','N/A'),
            'role':user.get('role',''),
            'exp': datetime.utcnow() + timedelta(seconds=ACCESS_TOKEN_EXPIRATION)
        }
        print(payload)
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        # Generate refresh token
        refresh_payload = {
            'email': email,
            'exp': datetime.utcnow() + timedelta(days=30)
        }
        refresh_token = jwt.encode(refresh_payload, REFRESH_SECRET_KEY, algorithm='HS256')
        
        table.update_item(
                Key={'email': email},
                UpdateExpression='SET refresh_token = :val1',
                ExpressionAttributeValues={
                    ':val1': refresh_token
                }
            )

        return generate_response(200, {'message': 'Login successful', 'user': {'email': email,'role':user.get('role','user')}, 'access_token': token, 'refreshToken': refresh_token})
        
    except Exception as e:
        return generate_response(500, {'message': f'Error: {str(e)}'})
        


def get_user_by_email(email):
    res = table.get_item(Key={'email':email})
    if 'Item' in res:
        print(res)
        return res['Item']
    else:
        return None
    

def get_object_by_id(id):
    res = table.get_item(Key={'host_id':id})
    if 'Item' in res:
        print(res)
        return res['Item']
    else:
        return None
    
    
def hash_api_key(api_key):
    """Hash the API key using bcrypt."""
    return bcrypt.hashpw(api_key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def generate_friendly_id(prefix="RES"):
    timestamp = int(time.time())  # Unix timestamp
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"{prefix}-{timestamp}-{random_part}"



def register_user(event):

    try:
        
        token = event['headers']['Authorization']
        if not token:
            return generate_response(403,{"message":"Missing token"})
        payload = verify_jwt(token)
        print(payload)
        if 'error' in payload:
            return generate_response(400, {'message': 'Invalid or expired token'})
        expected_email = payload['email']
        
        role = payload.get('role', 'user')  # Default to 'user' if not provided
        if not role in ['admin', 'user','guest']:
            return generate_response(400, {'message': 'Invalid role'})
        body = json.loads(event.get('body', '{}'))

        email = body.get('email')
        password = body.get('password')
        name = body.get('name')
        last_name = body.get("last_name")


        if not all([ password, email,name,last_name]):
            return generate_response(400, {'message': 'All fields are required'})
            
        if not email == expected_email:
            return generate_response(400,{"message":"Invalid email"})
        
        if get_user_by_email(email):
            return generate_response(400, {'message': 'user  already registered'})

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        confirmation_url = generate_url(email, "confirm")
        subject = "You have been added to Finbotix Solutions! Confirm Your Registration"
        body = ACCOUNT_CONFIRMATION_TEMPLATE.replace("{{confirmation_url}}", confirmation_url)
        send_email(email, subject, body)

        raw_api_key = secrets.token_urlsafe(32)
        hashed_api_key = hash_api_key(raw_api_key)


        # Store user details in DynamoDB
        table.put_item(
            Item={
            
           
                'email':email,
                'role':role,
                'name':name,
                'last_name':last_name,
                'password': hashed_password.decode('utf-8'),
                'verified':True,
                'api_key': hashed_api_key
            }
        )

        
        return generate_response(200, {'message': 'Airbnb registered successfully'})
        

    except Exception as e:
        return generate_response(500, {'message': f'Error: {str(e)}'}) 
        # return {
        #     'statusCode': 500,
        #     'headers': {
        #                     'Access-Control-Allow-Headers': 'Content-Type',
        #                     'Access-Control-Allow-Origin': '*',
        #                     'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
        #                 },
        #     'body': json.dumps({'message': 'An unexpected error occurred', 'error': str(e)})
        # }

def refresh_access_token(event):
    try:
        body = json.loads(event['body'])
        refresh_token = body['refreshToken']
        
        # Decode and verify the refresh token
        try:
            payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=['HS256'])
            email = payload.get('email')
        except jwt.ExpiredSignatureError:
            return generate_response(401, {'message': 'Refresh token has expired'})
            
        except jwt.InvalidTokenError:
            return generate_response(401, {'message': 'Invalid refresh token'})
            
        
        # Retrieve user from DynamoDB
        response = table.get_item(
            Key={'email': email}
        )
        
        if 'Item' not in response or response['Item'].get('refresh_token') != refresh_token:
            return generate_response(401, {'message': 'Invalid refresh token'})
            
        
        # Generate new access token
        access_payload = {
            'email': email,
            'exp':datetime.utcnow() + timedelta(seconds=ACCESS_TOKEN_EXPIRATION)
        }
        access_token = jwt.encode(access_payload, SECRET_KEY, algorithm='HS256')
        
        # Generate new refresh token
        new_refresh_payload = {
            'email': email,
            'exp': datetime.utcnow() + timedelta(days=30)
        }
        new_refresh_token = jwt.encode(new_refresh_payload, REFRESH_SECRET_KEY, algorithm='HS256')
        
        # Update refresh token in DynamoDB
        table.update_item(
            Key={'email': email},
            UpdateExpression='SET refresh_token = :val1',
            ExpressionAttributeValues={
                ':val1': new_refresh_token
            }
        )
        return generate_response(200, {'message': 'Access token refreshed', 'access_token': access_token, 'refreshToken': new_refresh_token})
        
    except ClientError as e:
        return generate_response(500, {'message': f'Error: {str(e)}'})
        



ACCOUNT_CONFIRMATION_TEMPLATE ="""<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>Confirm Your Registration</title>
    <style>
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(to right, #0f172a, #1e293b);
        color: white;
        padding: 30px;
        margin: 0;
      }
      .container {
        max-width: 600px;
        margin: 0 auto;
        background: #0f172a;
        border-radius: 12px;
        box-shadow: 0 0 15px rgba(59,130,246,0.5);
        padding: 40px;
      }
      h1 {
        color: #38bdf8;
        text-align: center;
      }
      p {
        line-height: 1.6;
        font-size: 16px;
      }
      .button {
        display: inline-block;
        margin-top: 30px;
        padding: 14px 28px;
        background: linear-gradient(to right, #3b82f6, #06b6d4);
        color: white;
        font-weight: bold;
        text-decoration: none;
        border-radius: 8px;
        text-align: center;
      }
      .footer {
        text-align: center;
        margin-top: 40px;
        font-size: 12px;
        color: #94a3b8;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Welcome to Finbotix Solutions 🚀</h1>
      <p>Hi there,</p>
      <p>Thank you for signing up!</p>
      <p>Please click the button below to confirm your registration:</p>
      <a href="{{confirmation_url}}" class="button">Confirm My Email</a>
      <p>If the button doesn't work, copy and paste the link below into your browser:</p>
      <p style="word-break: break-all;">{{confirmation_url}}</p>
      <div class="footer">
        © 2025 Finbotix.de • All rights reserved.
      </div>
    </div>
  </body>
</html>"""


PASSWORD_RESET_TEMPLATE ="""
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>Password Reset Request</title>
    <style>
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(to right, #0f172a, #1e293b);
        color: white;
        padding: 30px;
        margin: 0;
      }
      .container {
        max-width: 600px;
        margin: 0 auto;
        background: #0f172a;
        border-radius: 12px;
        box-shadow: 0 0 15px rgba(59,130,246,0.5);
        padding: 40px;
      }
      h1 {
        color: #38bdf8;
        text-align: center;
      }
      p {
        line-height: 1.6;
        font-size: 16px;
      }
      .button {
        display: inline-block;
        margin-top: 30px;
        padding: 14px 28px;
        background: linear-gradient(to right, #3b82f6, #06b6d4);
        color: white;
        font-weight: bold;
        text-decoration: none;
        border-radius: 8px;
        text-align: center;
      }
      .footer {
        text-align: center;
        margin-top: 40px;
        font-size: 12px;
        color: #94a3b8;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Password Reset Request 🔒</h1>
      <p>Hi there,</p>
      <p>We received a request to reset your password. Please click the link below to reset it:</p>
      <a href="{{reset_url}}" class="button">Reset My Password</a>
      <p>If the button doesn't work, copy and paste the following URL into your browser:</p>
      <p style="word-break: break-all;">{{reset_url}}</p>
      <div class="footer">
        © 2025 Finbotix.de • All rights reserved.
      </div>
    </div>
  </body>
</html>

"""