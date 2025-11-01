import json
import os
import boto3
import random
import string
from decimal import Decimal
from datetime import datetime, time
from boto3.dynamodb.conditions import Key
from collections import defaultdict
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import io
import jwt
import dateutil.parser
from dotenv import load_dotenv
load_dotenv()
# Initialize DynamoDB client
dynamodb = boto3.resource("dynamodb")
USER_TABLE = os.getenv("USER_TABLE", "airbnb-template-UsersTable-134858URA5K12")
APARTMENTS_TABLE = os.getenv(
    "APARTMENTS_TABLE", "airbnb-template-ApartmentsTable-11FK8JZ66KCGG"
)
BOOKINGS_TABLE = os.getenv(
    "BOOKINGS_TABLE", "airbnb-template-BookingsTable-WAQAVVKHTRTU"
)
GUESTS_TABLE = os.getenv("GUESTS_TABLE", "airbnb-template-GuestsTable-W0BJMETM78ZW")

BUCKET_NAME = os.environ.get(
    "BUCKET_NAME", ""
)
SECRET_KEY = os.environ.get("SECRET_KEY",'')
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "")

user = dynamodb.Table(USER_TABLE)
apartments = dynamodb.Table(APARTMENTS_TABLE)
bookings = dynamodb.Table(BOOKINGS_TABLE)
guests = dynamodb.Table(GUESTS_TABLE)

s3_client = boto3.client('s3', region_name='eu-central-1')
def lambda_handler(event, context):
    method = event.get("httpMethod")
    path = event.get("path")

    if method == "GET" and path == "/airbnb/api/private/host":
        return get_host(event)
    elif method =='GET' and path=='/airbnb/api/private/booking':
        return get_booking_data(event)
    
    elif method =='GET' and path=='/airbnb/api/private/document':
        return generate_presigned_url(event)
    
    elif method == "GET" and path == "/airbnb/api/private/bookings":
        return get_bookings(event)

    elif method == "PUT" and path == "/airbnb/api/private/host":
        return update_host(event)
    elif method == "PUT" and path == "/airbnb/api/private/booking":
        return update_booking(event)

    elif method == "GET" and path == "/airbnb/api/private/apartments":
        return get_apartments(event)

    elif method == "POST" and path == "/airbnb/api/private/apartment":
        return add_apartment(event)
    elif method == "POST" and path == "/airbnb/api/private/guests/submit":
        return submit_guests(event)
    
    elif method == "PUT" and path == "/airbnb/api/private/apartment/update":
        return update_apartment(event)

    elif method == "DELETE" and path == "/airbnb/api/private/apartment":
        return cancel_apartmnent(event)
    elif method == "GET" and path == "/airbnb/api/private/guest":
            return get_guest_data(event)

    elif method == "DELETE" and path == "/airbnb/api/private/document":
            return delete_guest_document(event)
        
    elif method == "DELETE" and path == "/airbnb/api/private/guest":
            return delete_guest(event)
    elif method == "POST" and path == "/airbnb/api/private/document/upload":
            return get_upload_presigned_url(event)
    elif method == "PUT" and path == "/airbnb/api/private/guest":
            return update_guest(event)
    else:
        return generate_response(
            400, {"message": "Invalid route or method", "method": method, "path": path}
        )


# Get user by email
def get_user_by_email(email):
    response = user.get_item(Key={"email": email})

    if "Item" in response:
        return response["Item"]
    else:
        return None


# Get user info
def get_host(event):
    email = event["requestContext"]["authorizer"].get("principalId")

    host = get_user_by_email(email)
    if not host:
        return generate_response(404, {"message": "Invalid email"})

    return generate_response(200, host)

def update_guest(event):
    try:
        body = json.loads(event["body"])
        booking_id = body.get("booking_id")
        guest_id = body.get("guest_id")

        if not booking_id or not guest_id:
            return generate_response(
                400, {"message": "Missing booking_id or guest_id"}
            )

        item = guests.get_item(
            Key={"booking_id": booking_id, "guest_id": guest_id}
        ).get("Item")
        
        if not item:
            return generate_response(404, {"message": "Guest not found"})

        update_expression_parts = []
        expression_values = {}
        expression_names = {}
        

        required_fields = [
           'tipo_allogiato','tipo_allogiato_code', 
           'data_arrivo',
           'giorni',
            'cognome','nome','sesso','data_nascita',
            
            'stato_nascita','stato_nascita_code',
            'cittadinanza','cittadinanza_code',
            
            'verified'
        ]
        if  'stato_nascita_code' not in body:
            return generate_response(
                400, {"message": "Missing stato_nascita_code"}
            )
        if body['stato_nascita_code'] in ["100000100"]:
            required_fields.extend(['comune_nascita','comune_nascita_code','provincia_nascita'])

        if 'tipo_allogiato_code' not  in body:
            return generate_response(
                400, {"message": "Missing tipo_allogiato_code"}
            )
        if  body['tipo_allogiato_code'] in ['16','17','18']:
            required_fields.extend(['selfie','front','back','tipo_documento','tipo_documento_code','numero_documento','luogo_rilascio_paese_code','luogo_rilascio_paese'])

        
        for field in required_fields:
            if field not in body:
                return generate_response(400, {"message": f"Missing required field: {field}"})
        additional_fields = ['luogo_rilascio_provincia','luogo_rilascio_comune_code','luogo_rilascio_comune']
        required_fields.extend(additional_fields)
        for field in required_fields:
            placeholder_value = f":{field}"
            attr_name = f"#{field}"
            
            expression_names[f"#{field}"] = field
            update_expression_parts.append(f"{attr_name} = {placeholder_value}")
            expression_values[placeholder_value] = body[field]
        
        if not update_expression_parts:
            return generate_response(400, {"message": "No valid fields to update"})
        response = guests.update_item(
            Key={"booking_id": booking_id, "guest_id": guest_id},
            UpdateExpression="SET " + ", ".join(update_expression_parts),
            ExpressionAttributeValues=expression_values,
            ExpressionAttributeNames=expression_names,
            ReturnValues="ALL_NEW",
        )
        
        updated_item = response.get("Attributes", {})
        return generate_response(200, convert_decimal(updated_item))
        
    
    except Exception as e:
        return generate_response(
            500, {"message": "Error updating guest", "error": str(e)}
        )

def get_guest_data(event):
    try:
        query = event["queryStringParameters"]
        booking_id = query.get("booking_id")
        guest_id = query.get("guest_id")

        if  not booking_id or not guest_id:
            return generate_response(
                400, {"message": "Missing apartment_id, booking_id or guest_id"}
            )

        item = guests.get_item(
            Key={"booking_id": booking_id, "guest_id": guest_id}
        ).get("Item")
        if not item:
            return generate_response(404, {"message": "Guest not found"})

        if item['selfie']:
            item['selfieUrl'] = json.loads(generate_presigned_url({
                "queryStringParameters": {
                    "file_key": item['selfie']
                }
            })['body'])['url']
        if item['front']:
            item['frontUrl'] = json.loads(generate_presigned_url({
                "queryStringParameters": {
                    "file_key": item['front']
                }
            })['body'])['url']
        if item['back']:
            item['backUrl'] = json.loads(generate_presigned_url({
                "queryStringParameters": {
                    "file_key": item['back']
                }
            })['body'])['url']
       
        return generate_response(200, convert_decimal(item))

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to fetch guest data", "error": str(e)}
        )

def delete_guest_document(event):
    try:
        query = event["queryStringParameters"]
        
        booking_id = query.get("booking_id")
        guest_id = query.get("guest_id")
        document_type = query.get("document_type")

        if  not booking_id or not guest_id or not document_type:
            return generate_response(
                400, {"message": "Missing apartment_id, booking_id, guest_id or document_type"}
            )

        item = guests.get_item(
            Key={"booking_id": booking_id, "guest_id": guest_id}
        ).get("Item")
        
        if not item:
            return generate_response(404, {"message": "Guest not found"})
        key_to_remove = item[document_type]
        if document_type == 'selfie':
            
            item['selfie'] = None
        elif document_type == 'front':
            item['front'] = None
        elif document_type == 'back':
            item['back'] = None
        else:
            return generate_response(400, {"message": "Invalid document type"})

        guests.put_item(Item=item)
        
        # Remove file from S3
        if key_to_remove:
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=key_to_remove)
        return generate_response(200, {"message": "Document deleted successfully"})

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to delete guest document", "error": str(e)}
        )

def get_upload_presigned_url(event):
    try:
        body = json.loads(event["body"])
        file_name = body["file_name"]
        file_extension = file_name.split(".")[-1]
        
        apartment_id = body["apartment_id"]
        booking_id = body["booking_id"]

        guest_id = body.get('guest_id',str(uuid.uuid4()))
        unique_key = f"uploads/{apartment_id}/{booking_id}/{guest_id}.{file_extension}"
        # unique_key = f"{guest_id}.{file_extension}"
        presigned_url = s3_client.generate_presigned_url(
            "put_object",
            Params={"Bucket": BUCKET_NAME, "Key": unique_key},
            ExpiresIn=3000,  # 5 minutes
        )
        return generate_response(
            200,
            {"uploadUrl": presigned_url, "fileKey": unique_key, "guest_id": guest_id},
        )

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to get presigned url", "error": str(e)}
        )



def get_booking_data(event):
    try:
        query = event["queryStringParameters"]
        apartment_id = query.get("apartment_id")
        booking_id = query.get("booking_id")

        if not apartment_id or not booking_id:
            return generate_response(
                400, {"message": "Missing apartment_id or booking_id"}
            )

        item = bookings.get_item(
            Key={"apartment_id": apartment_id, "booking_id": booking_id}
        ).get("Item")
        
        booking_guests = guests.query(
          
            KeyConditionExpression=Key("booking_id").eq(booking_id)
        ).get("Items", [])
        
        item['guests'] = booking_guests

        if not item:
            return generate_response(404, {"message": "Booking not found"})

        return generate_response(200, convert_decimal(item))
    
    except Exception as e:
        return generate_response(
            500, {"message": "Failed to fetch booking data", "error": str(e)}
        )
        
        
def generate_presigned_url(event):
    

    query_params = event.get("queryStringParameters", {})
    file_key = query_params.get("file_key")
    try:
        response = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET_NAME, 'Key': file_key},
            ExpiresIn=3600
        )
        return generate_response(200, {"url": response})
    except Exception as e:
        print(f"Error generating URL: {e}")
        return generate_response(500, {"message": "Failed to generate URL", "error": str(e)})

 

def generate_jwt(token_payload) -> str:
    """Generate a JWT for either 'confirm' or 'reset' mode."""
    
    token_payload['mode'] = 'documents_upload'
    
    token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")
    return token

def delete_guest(event):
    try:
        query = event["queryStringParameters"]
       
        booking_id = query.get("booking_id")
        guest_id = query.get("guest_id")

        if not booking_id or not guest_id:
            return generate_response(
                400, {"message": "Missing booking_id or guest_id"}
            )
        guest = guests.get_item(Key={"booking_id": booking_id, "guest_id": guest_id}).get("Item")
        
        if not guest:
            return generate_response(404, {"message": "Guest not found"})
        
        if guest.get('selfie'):
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=guest['selfie'])
            print(f"Deleted selfie: {guest['selfie']}")
        if guest.get('front'):
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=guest['front'])
            print(f"Deleted front: {guest['front']}")
            
        if guest.get('back'):
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=guest['back'])
            print(f"Deleted back: {guest['back']}")
            

        guests.delete_item(
            Key={"booking_id": booking_id, "guest_id": guest_id}
        )
        
        
        return generate_response(200, {"message": "Guest deleted successfully"})

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to delete guest", "error": str(e)}
        )
def update_booking(event):
    try:
        body = json.loads(event["body"])
        apartment_id = body.get("apartment_id")
        booking_id = body.get("booking_id")

        if not apartment_id or not booking_id:
            return generate_response(
                400, {"message": "Missing apartment_id or booking_id"}
            )

        
        pin = generate_4_digit_code()
        body['pin'] = pin
        required = ["checkin", 
                    "checkout",  
                    "notes", 
                    "number_of_guests",
                    'guest_email',
                    'guest_phone_number',
                    'pin',
                    'host_email',
                    'host_phone_number']
        for field in required:
            if field not in body:
                return generate_response(400, {"message": f"Missing required field: {field}"})
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
            'guest_email':body['guest_email'],
            'guest_phone_number':body['guest_phone_number'],
            'host_email':body['host_email'],
            'host_phone_number':body['host_phone_number']
        }
        booking_token = generate_jwt(token_payload)
        checkin_link = f'{FRONTEND_BASE_URL}checkin?token={booking_token}'
        
        checkin_str = body['checkin']
        checkin_date = datetime.strptime(checkin_str, "%Y-%m-%d")

        year = checkin_date.year
        month = checkin_date.month
        week = checkin_date.isocalendar()[1]
        body['year'] = year
        body['month'] = month
        body['week'] = week
        body['link'] = checkin_link
        body['token'] = booking_token
        update_expression_parts = []
        expression_values = {}
        expression_names = {}
        
        for key in ["checkin", "checkout",  'token',"notes", 'link',"number_of_guests",'year','month','week','guest_email','guest_phone_number','pin','host_email','host_phone_number']:
            if key in body:
                placeholder_value = f":{key}"
                attr_name = f"#{key}"
                
                expression_names[f"#{key}"] = key
                update_expression_parts.append(f"{attr_name} = {placeholder_value}")
                expression_values[placeholder_value] = body[key]

        if not update_expression_parts:
            return generate_response(400, {"message": "No valid fields to update"})

        response = bookings.update_item(
            Key={"apartment_id": apartment_id, "booking_id": booking_id},
            UpdateExpression="SET " + ", ".join(update_expression_parts),
            ExpressionAttributeValues=expression_values,
            ExpressionAttributeNames=expression_names,
            ReturnValues="ALL_NEW",
        )
        return generate_response(200, convert_decimal(response["Attributes"]) )

    except Exception as e:
        return generate_response(
            500, {"message": "Error updating booking", "error": str(e)}
        )
# Update host
def update_host(event):
    try:
        body = json.loads(event["body"])
        email = event["requestContext"]["authorizer"].get("principalId")
        if not email:
            return generate_response(400, {"message": "Missing email"})

        update_expression_parts = []
        expression_values = {}
        expression_names = {}

        for key in ["name", "last_name"]:
            if key in body:
                placeholder_name = f"#{key}"
                placeholder_value = f":{key}"
                update_expression_parts.append(
                    f"{placeholder_name} = {placeholder_value}"
                )
                expression_values[placeholder_value] = body[key]
                expression_names[placeholder_name] = key

        if not update_expression_parts:
            return generate_response(400, {"message": "No valid fields to update"})

        response = user.update_item(
            Key={"email": email},
            UpdateExpression="SET " + ", ".join(update_expression_parts),
            ExpressionAttributeValues=expression_values,
            ExpressionAttributeNames=expression_names,
            ReturnValues="ALL_NEW",
        )
        return generate_response(200, response["Attributes"])

    except Exception as e:
        return generate_response(
            500, {"message": "Error updating host", "error": str(e)}
        )


# Get apartments
def get_apartments(event):
    try:
        response = apartments.scan()
        return generate_response(200, response.get("Items", []))
    except Exception as e:
        return generate_response(
            500, {"message": "Failed to fetch apartments", "error": str(e)}
        )


def generate_apartment_code(prefix="APT"):
    letters = "".join(random.choices(string.ascii_uppercase, k=3))
    digits = "".join(random.choices(string.digits, k=3))
    suffix = "".join(random.choices(string.ascii_uppercase, k=2))
    return f"{prefix}-{letters}{digits}{suffix}"


def add_apartment(event):
    try:
        body = json.loads(event["body"])
        email = event["requestContext"]["authorizer"].get("principalId")
        required_fields = ["street", "city", "postcode", "country",'host_email','host_phone_number']
        for field in required_fields:
            if field not in body:
                return generate_response(
                    400, {"message": f"Missing required field: {field}"}
                )

        apartment_id = body.get("apartment_id", generate_apartment_code())
        apartment = {
            "apartment_id": apartment_id,
            "street": body["street"],
            "city": body["city"],
            "postcode": body["postcode"],
            "country": body["country"],
            "apartment_code": apartment_id,
            "room_no": body.get("room_no", None),
            "created_at": datetime.utcnow().isoformat(),
            "host_email": email,
            "host_phone_number": body.get("host_phone_number", None),
        }
        apartments.put_item(Item=apartment)
        return generate_response(201, apartment)

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to add apartment", "error": str(e)}
        )

def get_bookings(event):
    try:
        params = event.get("queryStringParameters", {}) or {}
        date_str = params.get("date")
      
        month = params.get("month")
        year = params.get("year")
        apartment_id_filter = params.get("apartment_id")

        bookings_list = []

        # Prioritize exact date if provided
        if date_str:
            response = bookings.query(
                IndexName="CheckinDateIndex",
                KeyConditionExpression=Key("checkin").eq(date_str)
            )
            bookings_list = response.get("Items", [])

        # Handle year + month
        elif year and month:
            year = int(year)
            month = int(month)
            response = bookings.query(
                IndexName="MonthIndex",
                KeyConditionExpression=Key("month").eq(month)
            )
            bookings_list = [item for item in response.get("Items", []) if int(item.get("year", -1)) == year]

        # Handle year only
        elif year:
            year = int(year)
            response = bookings.query(
                IndexName="YearIndex",
                KeyConditionExpression=Key("year").eq(year)
            )
            bookings_list = response.get("Items", [])

        
 
        else:
            return generate_response(400, {"message": "Missing valid filter parameter"})

        # Optional apartment filter
        if apartment_id_filter:
            bookings_list = [item for item in bookings_list if item.get("apartment_id") == apartment_id_filter]

        # Group by apartment
        grouped = defaultdict(list)
        for item in bookings_list:
            grouped[item["apartment_id"]].append(item)

        return generate_response(200, convert_decimal(dict(grouped)))

    except Exception as e:
        print("Error in get_bookings:", str(e))
        return generate_response(500, {"message": "Internal server error"})
    


def submit_guests(event):
    try:
        body = json.loads(event.get('body','{}'))

        required = [ "apartment_id", "booking_id"]

        for field in required:
            if field not in body:
                return generate_response(
                    400, {"message": f"Missing required field: {field}"}
                )

        booking = bookings.get_item(
            Key={
                "apartment_id": body["apartment_id"],
                "booking_id": body["booking_id"],
            }
        ).get("Item")
        
        if not booking:
            return generate_response(403, {"message": "Invalid booking_id"})

        apartmnet = apartments.get_item(
            Key={"apartment_id": body["apartment_id"]}).get("Item")
        if not apartmnet:
            return generate_response(403, {"message": "Invalid apartment_id"})
        
        host_email = apartmnet["host_email"]
        response = guests.query(
            KeyConditionExpression=Key("booking_id").eq(body["booking_id"])
        )
        response = response["Items"]
  

        txt_content = create_guest_txt_grouped(response,apartmnet['apartment_id'])
       
        
        txt_content = "\r\n".join(txt_content)
        booking_url = f"{FRONTEND_BASE_URL}/booking?booking_id={booking['booking_id']}&apartment_id={apartmnet['apartment_id']}"
        
        email_body = EMAIL_EXPORT_FILE.replace("{BOOKING_ID}", booking['booking_id']).replace("{BOOKING_URL}", booking_url).replace("{CHECKIN}", booking['checkin']).replace("{GUESTS_NUMBER}", str(booking['number_of_guests']))
        send_txt_email_via_ses(
            subject=f"[{booking['booking_id']}] Ospiti registrati - Airbnb",
            body_text="In allegato trovi il file .txt con i dati degli ospiti.",
            body_html=email_body,
            to_email=host_email,
            from_email="airbnb@airbnb.finbotix.de",
            filename=f"{body['booking_id']}.txt",
            txt_content=txt_content,
        )

        send_txt_email_via_ses(
            subject=f"[{body['booking_id']}] Verification completed. Your PIN is {booking['pin']}",
            body_text=f"Thank you for completing the verification process, the PIN for the door is {booking['pin']}",
            body_html=generate_verification_email_html(booking['booking_id'], booking['pin'], None),
            to_email=booking['guest_email'],
            from_email="airbnb@airbnb.finbotix.de",
            filename=None,
            txt_content=None
        )
        
        # Save file
        file_key = f"uploads/{body['apartment_id']}/{body['booking_id']}/export_{body['booking_id']}.txt"
        s3_client.put_object(Bucket=BUCKET_NAME, Key=file_key, Body=txt_content)
        
        # Mark booking as completed
        bookings.update_item(Key={'apartment_id':body['apartment_id'],'booking_id':body['booking_id']},
                             UpdateExpression='SET completed = :val, export_file = :export_file',
                             ExpressionAttributeValues={':val':True,':export_file': file_key},
                             ReturnValues ='UPDATED_NEW'
                             )
        # Mark guests as verified
        for guest in response:
            guests.update_item(
                Key={
                    "booking_id": body["booking_id"],
                    "guest_id": guest["guest_id"],
                },
                UpdateExpression="SET sent = :val",
                ExpressionAttributeValues={":val": True},
                ReturnValues="UPDATED_NEW",
            )
            
        
        return generate_response(
            201, convert_decimal({"message": "Documents uploaded",'file_key':file_key})
        )

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to add guest", "error": str(e)}
        )

def send_txt_email_via_ses(
    subject, body_text,body_html, to_email, from_email, filename, txt_content
):
    # Crea client SES
    ses = boto3.client(
        "ses", region_name="eu-central-1"
    )  # Cambia se usi una regione diversa

    # Email MIME
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    # Corpo del messaggio
    # Alternative part for plain text and HTML
    body = MIMEMultipart("alternative")
 
    body.attach(MIMEText(body_html, "html"))
    msg.attach(body)

    # Genera file txt in memoria (buffer)
    if txt_content:
        txt_buffer = io.BytesIO(txt_content.encode("utf-8"))

        # Allegato
        attachment = MIMEApplication(txt_buffer.read())
        attachment.add_header("Content-Disposition", "attachment", filename=filename)
        msg.attach(attachment)

    # Invia con SES
    response = ses.send_raw_email(
        Source=from_email, Destinations=[to_email], RawMessage={"Data": msg.as_string()}
    )

    print("✅ Email inviata! Message ID:", response["MessageId"])
    return response


def create_guest_txt_grouped(data,apartment_id, filename="ospiti.txt"):
    """Crea il file txt ordinato per Capo Famiglia e Componenti, senza CRLF finale."""
    capi = []
    altri = []
    main_guests = ['16','17','18']
    for guest in data:
        tipo_allogiato_code = guest.get("tipo_allogiato_code", "").lower()
        if  tipo_allogiato_code in main_guests:
            capi.append(guest)
        else:
            altri.append(guest)

    # Gruppo per booking_id (stesso gruppo familiare)
    gruppi = {}
    for guest in capi + altri:
        booking_id = guest.get("booking_id", "default")
        gruppi.setdefault(booking_id, []).append(guest)

    lines = []

    # Ordina i gruppi per Capo Famiglia prima, poi componenti
    for booking_id, ospiti in gruppi.items():
        capo = [g for g in ospiti if  g.get("tipo_allogiato_code", "").lower() in main_guests]
        componenti = [
            g for g in ospiti if  g.get("tipo_allogiato_code", "").lower() not in main_guests
        ]
        gruppo_ordinato = capo + componenti
        for g in gruppo_ordinato:
            lines.append(build_guest_line(g,apartment_id))

    return lines

def build_guest_line(guest,apartment_id="000000"):
    luogo_rilascio_code = guest.get('luogo_rilascio_paese_code') if not 'luogo_rilascio_comune_code' in guest else guest.get('luogo_rilascio_comune_code')
    print(f"Building guest line for {guest.get('nome', '')} {guest.get('cognome', '')} with luogo_rilascio_code: {luogo_rilascio_code}")
    """Crea una riga formattata per un ospite."""
    line = ""
    line += pad(guest.get("tipo_allogiato_code", ""), 2)
    line += pad(format_date(guest.get("data_arrivo")), 10)
    line += pad(guest.get("giorni", ""), 2, align_left=False)
    line += pad(guest.get("cognome", ""), 50)
    line += pad(guest.get("nome", ""), 30)
    line += pad(guest.get("sesso", ""), 1)
    line += pad(format_date(guest.get("data_nascita")), 10)
    line += pad(guest.get("comune_nascita_code", ""), 9)
    line += pad(guest.get("provincia_nascita", ""), 2)
    line += pad(guest.get("stato_nascita_code", ""), 9)
    line += pad(guest.get("cittadinanza_code", ""), 9)
    line += pad(guest.get("tipo_documento_code", ""), 5)
    line += pad(guest.get("numero_documento", ""), 20)
    line += pad(luogo_rilascio_code, 9)
    line += pad(apartment_id,6)
    return line
def format_date(date_str):
    """Converti data da 'YYYY-MM-DD' a 'dd/MM/yyyy'."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").strftime("%d/%m/%Y")
    except Exception:
        return " " * 10


def pad(value, length, align_left=True):
    """Pad o taglia una stringa a lunghezza fissa."""
    if value is None:
        value = ""
    value = str(value)
    if len(value) > length:
        return value[:length]
    return value.ljust(length) if align_left else value.rjust(length)



def update_apartment(event):
    try:
        body = json.loads(event["body"])
        apartment_id = body.get("apartment_id")
        if not apartment_id:
            return generate_response(400, {"message": "Missing apartment_id"})

        # Verify apartment belongs to host
        response = apartments.get_item(Key={"apartment_id": apartment_id})
        item = response.get("Item")
        if not item:
            return generate_response(
                400, {"message": "Unauthorized or invalid apartment"}
            )

        update_expression = []
        expression_values = {}
        for key in ["street", "city", "postcode", "country", "room_no"]:
            if key in body:
                update_expression.append(f"{key} = :{key}")
                expression_values[f":{key}"] = body[key]

        if not update_expression:
            return generate_response(400, {"message": "No valid fields to update"})

        response = apartments.update_item(
            Key={"apartment_id": apartment_id},
            UpdateExpression="SET " + ", ".join(update_expression),
            ExpressionAttributeValues=expression_values,
            ReturnValues="ALL_NEW",
        )
        return generate_response(200, response["Attributes"])

    except Exception as e:
        return generate_response(
            500, {"message": "Error updating apartment", "error": str(e)}
        )


def cancel_apartmnent(event):
    try:
        query = event["queryStringParameters"]

        apartment_id = query.get("apartment_id")
        if not apartment_id:
            return generate_response(400, {"message": "Missing apartment_id"})

        apartment = apartments.get_item(Key={"apartment_id": apartment_id}).get("Item")
        if not apartment:
            return generate_response(400, {"message": "Unauthorized or not found"})

        apartments.delete_item(Key={"apartment_id": apartment_id})
        return generate_response(200, {"message": "Apartment cancelled"})

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to cancel apartment", "error": str(e)}
        )


def generate_4_digit_code():
    return f"{random.randint(0, 9999):04d}"


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

def generate_verification_email_html(booking_id, pin, booking_url):
    return f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f9f9f9;
                padding: 3px;
                color: #333;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background-color: #fff;
                padding: 10px;
                border-radius: 12px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.05);
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
            }}
            .header h2 {{
                color: #4f46e5;
            }}
            .pin {{
                font-size: 24px;
                font-weight: bold;
                color: #16a34a;
                background: #ecfdf5;
                padding: 12px 20px;
                display: inline-block;
                border-radius: 8px;
                margin: 20px 0;
            }}
            .button {{
                display: inline-block;
                background-color: #4f46e5;
                color: white;
                padding: 12px 20px;
                text-decoration: none;
                border-radius: 8px;
                margin-top: 20px;
            }}
            .footer {{
                margin-top: 40px;
                font-size: 12px;
                color: #888;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Verifica completata 🎉</h2>
                <p>Il processo di registrazione è andato a buon fine.</p>
            </div>

            <p>Grazie per aver completato la registrazione. Il tuo codice PIN per il check-in è:</p>

            <div class="pin">{pin}</div>

            

            <div class="footer">
                Email automatica inviata da Finbotix per conto di Airbnb | Booking ID: {booking_id}
            </div>
        </div>
    </body>
    </html>
    """

EMAIL_EXPORT_FILE ="""
<!DOCTYPE html>
<html lang="en" style="font-family: Arial, sans-serif;">
  <head>
    <meta charset="UTF-8" />
    <title>Guest Registration</title>
  </head>
  <body style="background-color: #f9fafb; margin: 0; padding: 1rem;">
    <div style="max-width: 600px; margin: auto; background: white; padding: 1rem; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.05);">
      <h2 style="color: #111827; font-size: 24px;">📝 Ospiti registrati</h2>
      <p style="font-size: 16px; color: #374151; margin-top: 1rem;">
        Ciao,
      </p>
      <p style="font-size: 16px; color: #374151;">
        In allegato trovi il file <strong>{BOOKING_ID}.txt</strong> con i dati registrati degli ospiti per la tua prenotazione Airbnb.
      </p>
      <p style="font-size: 16px; color: #374151;">
        Puoi aprirlo e conservarlo per i tuoi archivi. Se desideri rivedere o modificare i dati della prenotazione, puoi farlo cliccando qui:
      </p>
      
      <div style="text-align: center; margin: 1rem 0;">
        <a href="{BOOKING_URL}" target="_blank" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: 500;">
          🔗 Prenotazione
        </a>
      </div>

      <div style="padding: 1rem; background-color: #f3f4f6; border-left: 4px solid #6366f1;">
        <p style="margin: 0; color: #4b5563;"><strong>Booking ID:</strong> {BOOKING_ID}</p>
        <p style="margin: 0; color: #4b5563;"><strong>Check-in:</strong> {CHECKIN}}</p>
        <p style="margin: 0; color: #4b5563;"><strong>Guests:</strong>{GUESTS_NUMBER}</p>
      </div>

      <p style="font-size: 14px; color: #9ca3af; margin-top: 2rem;">
        Questo messaggio è stato inviato automaticamente da  Finbotix. Per supporto, contattaci a <a href="mailto:alessio.giovannini@finbotix.de" style="color: #6b7280;">alessio.giovannini@finbotix.de</a>.
      </p>
    </div>
  </body>
</html>
"""