import json
import os
import boto3

import random
import jwt
from decimal import Decimal
from datetime import datetime ,time
from dotenv import load_dotenv
load_dotenv()

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
USERS_TABLE = os.getenv("USERS_TABLE", "")
APARTMENTS_TABLE = os.getenv(
    "APARTMENTS_TABLE", ""
)
BOOKINGS_TABLE = os.getenv(
    "BOOKINGS_TABLE", ""
)
GUESTS_TABLE = os.getenv("GUESTS_TABLE", "")
JWT_EXPIRATION = int(os.environ.get('JWT_EXPIRATION', int(3600)))
SECRET_KEY = os.environ.get("SECRET_KEY",'')

FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "")
hosts = dynamodb.Table(USERS_TABLE)
apartments = dynamodb.Table(APARTMENTS_TABLE)
bookings = dynamodb.Table(BOOKINGS_TABLE)
guests=dynamodb.Table(GUESTS_TABLE)


def convert_decimal(obj):
    if isinstance(obj, list):
        return [convert_decimal(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    else:
        return obj



def generate_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS,PUT",
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
        },
        "body": json.dumps(body),
    }


def lambda_handler(event, context):
    method = event.get("httpMethod")
    path = event.get("path")

    
    if method == 'POST' and path == '/airbnb/api/agent/booking':
        return add_booking(event)
    else:
        return generate_response(400, {
            "message": "Invalid route or method",
            "method": method,
            "path": path
        })



def generate_4_digit_code():
    return f"{random.randint(0, 9999):04d}"


    
def generate_jwt(token_payload) -> str:
    """Generate a JWT for either 'confirm' or 'reset' mode."""
    
    token_payload['mode'] = 'documents_upload'
    
    token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")
    return token

def get_booking_by_id(apartment_id,booking_id):
    item = bookings.get_item(Key={'apartment_id':apartment_id,'booking_id':booking_id}).get('Item')
    return item



def add_booking(event):
    try:
        body = json.loads(event['body'])

        required = ['apartment_id', 'booking_id',  'checkin', 'checkout', 'days', 'number_of_guests','guest_phone_number','guest_email','host_phone_number','host_email']
        for field in required:
            if field not in body:
                return generate_response(400, {"message": f"Missing required field: {field}"})
        apartment = apartments.get_item(Key={'apartment_id': body['apartment_id']}).get('Item')
        if not apartment:
            return generate_response(403, {"message": "Unauthorized or not found apartment"})
        
        booking_id = body.get("booking_id")
        if get_booking_by_id(body['apartment_id'],booking_id):
            return generate_response(400,{"message":"Booking already exists"})
        guest_email = body.get("guest_email",'alessiogiovannini23@gmail.com')
        guest_phone_number = body.get("guest_phone_number",'alessiogiovannini23@gmail.com')
        host_email = apartment.get("host_email",'alessiogiovannini23@gmail.com')
        host_phone_number = apartment.get("host_phone_number",'alessiogiovannini23@gmail.com')
        
        pin = generate_4_digit_code()
        date_only = datetime.strptime(body['checkin'], "%Y-%m-%d")
        expiration = datetime.combine(date_only.date(), time(hour=13, minute=0))
        print(expiration)
        token_payload = {
            'apartment_id':body['apartment_id'],
            'booking_id':body['booking_id'],
            'checkin': body['checkin'],
            'exp':int(expiration.timestamp()),
            'checkout': body['checkout'],
            'number_of_guests': int(body['number_of_guests']),
            'guest_email':guest_email,
            'guest_phone_number':guest_phone_number,
            'host_email':host_email,
            'host_phone_number':host_phone_number
        }
        booking_token = generate_jwt(token_payload)
        checkin_link = f'https://airbnb.finbotix.de/checkin?token={booking_token}'
        
        checkin_str = body['checkin']
        checkin_date = datetime.strptime(checkin_str, "%Y-%m-%d")

        year = checkin_date.year
        month = checkin_date.month
        week = checkin_date.isocalendar()[1]
        booking = {
            'booking_id': body['booking_id'],
            'apartment_id': body['apartment_id'],
            'token':booking_token,
            'documents_deadline':str(expiration),
            'pin': str(pin),
            'link':checkin_link,
            'checkin': body['checkin'],
            'checkout': body['checkout'],
            'days': int(body['days']),
            'number_of_guests': int(body['number_of_guests']),
            'notes': body.get('notes', ''),
            'guest_phone_number': guest_phone_number,
            'guest_email':guest_email,
            'host_phone_number':host_phone_number,
            'host_email':host_email,
            'doc_uploaded': body.get('doc_uploaded', False),
            'created_at': datetime.utcnow().isoformat(),
            'year': year,
            'month': month,
            'week': week
        }

        bookings.put_item(Item=booking)
        return generate_response(201, booking)

    except Exception as e:
        return generate_response(500, {"message": "Failed to add booking", "error": str(e)})

