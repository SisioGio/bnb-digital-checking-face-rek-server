import json
import os
import boto3
from decimal import Decimal
from datetime import datetime
import uuid
from boto3.dynamodb.conditions import Key
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import jwt
import io
import base64
import pandas as pd
import difflib

from dotenv import load_dotenv
load_dotenv()

# Initialize DynamoDB client
dynamodb = boto3.resource("dynamodb")
USERS_TABLE = os.getenv("USERS_TABLE", "")
APARTMENTS_TABLE = os.getenv(
    "APARTMENTS_TABLE", ""
)
BOOKINGS_TABLE = os.getenv(
    "BOOKINGS_TABLE", ""
)
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL")
GUESTS_TABLE = os.getenv("GUESTS_TABLE", "airbnb-template-GuestsTable-W0BJMETM78ZW")
JWT_EXPIRATION = int(os.environ.get("JWT_EXPIRATION", int(3600)))
SECRET_KEY = os.environ.get(
    "SECRET_KEY", ""
)


rekognition_client = boto3.client("rekognition")
s3_client = boto3.client("s3", region_name="eu-central-1")
BUCKET_NAME = os.environ.get(
    "BUCKET_NAME", ""
)
ses_client = boto3.client("ses")
client = boto3.client("bedrock-runtime")
users = dynamodb.Table(USERS_TABLE)
apartments = dynamodb.Table(APARTMENTS_TABLE)
bookings = dynamodb.Table(BOOKINGS_TABLE)
guests = dynamodb.Table(GUESTS_TABLE)


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

    if method == "POST" and path == "/airbnb/api/guest/guest":
        return add_guest(event)
    elif method == "DELETE" and path == "/airbnb/api/guest/guest":
        return delete_guest(event)
    elif method == "GET" and path == "/airbnb/api/guest/guest":
        return get_guests(event)
    elif method == "POST" and path == "/airbnb/api/guest/submit":
        return submit_guests(event)
    elif method == "POST" and path == "/airbnb/api/guest/uploadurl":
        return get_presigned_url(event)
    elif method == "POST" and path == "/airbnb/api/guest/extract":
        return extract_document_data(event)
    elif method == "POST" and path == "/airbnb/api/guest/verify":
        return validate_identity(event)
    else:
        return generate_response(
            400, {"message": "Invalid route or method", "method": method, "path": path}
        )


def verify_jwt(token: str) -> dict:
    """Verify JWT and return payload."""
    try:
        print(SECRET_KEY)
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}
    except Exception as e:
        print(f"Error verifying JWT: {e}")
        return {"error": "Token verification failed"}
    


def verify_checkin_token(event):
    token = event["headers"]["Authorization"]
    if 'Bearer ' in token:
        token = token.split('Bearer ')[-1]
        
    decoded = verify_jwt(token)
    if "error" in decoded:
        return None,decoded['error']
    return decoded


def get_guests(event):
    try:
        print(event)
       
        token,msg = verify_checkin_token(event)
        if not token:
            return generate_response(403, {"message": msg})

        booking_id = token.get("booking_id")

        response = guests.query(KeyConditionExpression=Key("booking_id").eq(booking_id))
        
        booking = bookings.get_item(
            Key={
                "apartment_id": token["apartment_id"],
                "booking_id": booking_id,
            }
        ).get("Item")
        
        if not booking:
            return generate_response(403, {"message": "Invalid booking_id"})
        booking_complete = booking.get("completed", False)
        return generate_response(200, {'guests':convert_decimal(response.get("Items", [])),'booking_complete':booking_complete})
    except Exception as e:
        return generate_response(
            500, {"message": "Failed to get guests", "error": str(e)}
        )


def submit_guests(event):
    try:
        token,msg = verify_checkin_token(event)
        if not token:
            return generate_response(403, {"message": msg})

        required = [ "apartment_id", "booking_id"]

        for field in required:
            if field not in token:
                return generate_response(
                    400, {"message": f"Missing required field: {field}"}
                )

        booking = bookings.get_item(
            Key={
                "apartment_id": token["apartment_id"],
                "booking_id": token["booking_id"],
            }
        ).get("Item")
        
        if not booking:
            return generate_response(403, {"message": "Invalid booking_id"})

        
        
        host_email = token["host_email"]
        response = guests.query(
            KeyConditionExpression=Key("booking_id").eq(token["booking_id"])
        )
        response = response["Items"]
        booking_people = booking["number_of_guests"]
        if len(response) < int(booking_people):
            return generate_response(
                400,
                {"message": f"Invalid number of guests,mininum is {booking_people}"},
            )
        # Get main guest (guest with tipo_allogiato_code in ["16", "17", "18"])
        main_guest = next(
            (guest for guest in response if guest["tipo_allogiato_code"] in ["16", "17", "18"]),
            None,
        )
        if not main_guest:
            return generate_response(
                400, {"message": "Main guest not found. Please ensure at least one guest is registered with type 'Capo Famiglia' or 'Capo Gruppo' or 'Ospite Singolo'."}
                
            )
        # Check if all guests have completed the verification process
        
        if not all(guest['verified'] for guest in response if guest['tipo_allogiato_code'] not in ["19", "20"]):
            return generate_response(
                400, {"message": "Not all 'main' guests completed the verification process"}
            )
            
        

        txt_content = create_guest_txt_grouped(response,token['apartment_id'])
        txt_content = "\r\n".join(txt_content)
        booking_url = f"{FRONTEND_BASE_URL}/booking?booking_id={token['booking_id']}&apartment_id={token['apartment_id']}"
        
        email_body = EMAIL_EXPORT_FILE.replace("{BOOKING_ID}", token['booking_id']).replace("{BOOKING_URL}", booking_url).replace("{CHECKIN}", booking['checkin']).replace("{GUESTS_NUMBER}", str(booking_people))
        send_txt_email_via_ses(
            subject=f"[{token['booking_id']}] Ospiti registrati - Airbnb",
            body_text="In allegato trovi il file .txt con i dati degli ospiti.",
            body_html=email_body,
            to_email=host_email,
            from_email="finbotix@airbnb.finbotix.de",
            filename=f"{token['booking_id']}.txt",
            txt_content=txt_content,
        )

        customer_notification_body = generate_verification_email_html(token['booking_id'], booking['pin'],None)
        send_txt_email_via_ses(
            subject=f"[{token['booking_id']}] Verification completed. Your PIN is {booking['pin']}",
            body_text=f"Thank you for completing the verification process, the PIN for the door is {booking['pin']}",
            body_html =customer_notification_body,
            to_email=token['guest_email'],
            
            from_email="finbotix@airbnb.finbotix.de",
            filename=None,
            txt_content=None
        )
        
        # Save file
        file_key = f"uploads/{token['apartment_id']}/{token['booking_id']}/export_{token['booking_id']}.txt"
        s3_client.put_object(Bucket=BUCKET_NAME, Key=file_key, Body=txt_content)
        
        # Mark booking as completed
        bookings.update_item(Key={'apartment_id':token['apartment_id'],'booking_id':token['booking_id']},
                             UpdateExpression='SET completed = :val, export_file = :export_file',
                             ExpressionAttributeValues={':val':True,':export_file': file_key},
                             ReturnValues ='UPDATED_NEW'
                             )
        # Mark guests as verified
        for guest in response:
            guests.update_item(
                Key={
                    "booking_id": token["booking_id"],
                    "guest_id": guest["guest_id"],
                },
                UpdateExpression="SET sent = :val",
                ExpressionAttributeValues={":val": True},
                ReturnValues="UPDATED_NEW",
            )
        return generate_response(
            201, convert_decimal({"message": "Documents uploaded"})
        )

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to add guest", "error": str(e)}
        )


def delete_guest(event):
    try:
        query = event["queryStringParameters"]
        token,msg = verify_checkin_token(event)
        if not token:
            return generate_response(403, {"message": msg})
        guest_id = query.get("guest_id")
        booking_id = token["booking_id"]
        if not booking_id or not guest_id:
            return generate_response(
                400, {"message": "Missing apartment_id  or booking_id or guest_id"}
            )

        guest = guests.get_item(
            Key={"booking_id": booking_id, "guest_id": guest_id}
        ).get("Item")
        if not guest:
            return generate_response(400, {"message": "Guest not found"})

        guests.delete_item(Key={"booking_id": booking_id, "guest_id": guest_id})
        return generate_response(200, {"message": "Guest cancelled"})

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to cancel guest", "error": str(e)}
        )


def get_presigned_url(event):
    try:
        body = json.loads(event["body"])
        file_name = body["fileName"]
        file_extension = file_name.split(".")[-1]
        
        apartment_id = body["apartment_id"]
        booking_id = body["booking_id"]

        guest_id = str(uuid.uuid4())
        unique_key = f"uploads/{apartment_id}/{booking_id}/{guest_id}.{file_extension}"
        # unique_key = f"{guest_id}.{file_extension}"
        presigned_url = s3_client.generate_presigned_url(
            "put_object",
            Params={"Bucket":BUCKET_NAME, "Key": unique_key},
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


def add_guest(event):
    try:
        token,msg = verify_checkin_token(event)
        if not token:
            return generate_response(403, {"message": msg})
        booking_id = token.get("booking_id")
        apartment_id = token.get("apartment_id")
        response = bookings.get_item(
            Key={"apartment_id": apartment_id, "booking_id": booking_id}
        ).get("Item")
        if not response:
            return generate_response(400, {"message": "Invalid booking parameters"})
        checkin = response["checkin"]
        duration = response["days"]

        body = json.loads(event["body"])
        valid, errors = validate_guest_data(body)

        if not valid:
            return generate_response(400, errors)
        if body["tipo_allogiato_code"] in ["19", "20"]:
            guest_id = str(uuid.uuid4())
        else:
            guest_id = body.get("numero_documento",str(uuid.uuid4()))
            
            
        guest = guests.get_item(
            Key={"booking_id": booking_id, "guest_id": guest_id}
        ).get("Item")
        
        if guest:
            return generate_response(
                400, {"numero_documento": "Duplicate document number"}
            )

        guest = {
            "guest_id": guest_id,
            "booking_id": booking_id,
            "tipo_allogiato": body.get("tipo_allogiato"),
            "tipo_allogiato_code": body.get("tipo_allogiato_code"),
            "data_arrivo": checkin,
            "giorni": duration,
            "nome": body.get("nome"),
            "cognome": body.get("cognome"),
            "data_nascita": body.get("data_nascita"),
            "sesso": body.get("sesso"),
            "comune_nascita": body.get("comune_nascita"),
            "comune_nascita_code": body.get("comune_nascita_code"),
            "provincia_nascita": body.get("provincia_nascita"),
            "stato_nascita": body.get("stato_nascita"),
            "stato_nascita_code": body.get("stato_nascita_code"),
            "cittadinanza": body.get("cittadinanza"),
            "cittadinanza_code": body.get("cittadinanza_code"),
            "tipo_documento": body.get("tipo_documento"),
            "tipo_documento_code": body.get("tipo_documento_code"),
            "numero_documento": body.get("numero_documento"),
            "luogo_rilascio_paese_code": body.get("luogo_rilascio_paese_code"),
            "luogo_rilascio_paese": body.get("luogo_rilascio_paese"),
             "luogo_rilascio_provincia": body.get("luogo_rilascio_provincia"),
            "luogo_rilascio_comune_code": body.get("luogo_rilascio_comune_code"),
             "luogo_rilascio_comune": body.get("luogo_rilascio_comune"),
          
            
            "created_at": datetime.utcnow().isoformat(),
            "sent": False,
            "verified": False,
        }
        guests.put_item(Item=guest)
        return generate_response(
            200, {"message": "Data submitted", "guest_id": guest_id}
        )

    except Exception as e:
        print("Failed to add guest" + str(e))
        return None


def extract_document_data(event):
    try:
        token,msg = verify_checkin_token(event)
        if not token:
            return generate_response(403, {"message": msg})

        booking_id = token.get("booking_id")
        apartment_id = token.get("apartment_id")

        response = bookings.get_item(
            Key={"apartment_id": apartment_id, "booking_id": booking_id}
        ).get("Item")
        if not response:
            return generate_response(400, {"message": "Invalid booking parameters"})
        
        body = json.loads(event["body"])
        files = body["files"]
        images = []
        for image in files:
            s3_response = s3_client.get_object(
                Bucket=BUCKET_NAME, Key=image["key"]
            )
            image_bytes = s3_response["Body"].read()
            encoded_image = base64.b64encode(image_bytes).decode("utf-8")
            images.append(
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": encoded_image,
                    },
                }
            )

        response = analyze_document(images)
        json_response = json.loads(response)
        modified_data = post_process_data(json_response)
        return generate_response(201, modified_data)

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to add guest", "error": str(e)}
        )


def validate_identity(event):
    try:
        body = json.loads(event["body"])
        token,msg = verify_checkin_token(event)
        if not token:
            return generate_response(403, {"message": msg})
        required = ["apartment_id", "booking_id"]
        for field in required:
            if field not in token:
                return generate_response(
                    400, {"message": f"Missing required field: {field}"}
                )

        booking = bookings.get_item(
            Key={
                "apartment_id": token["apartment_id"],
                "booking_id": token["booking_id"],
            }
        ).get("Item")
        if not booking:
            return generate_response(403, {"message": "Invalid booking_id"})

        selfie = body["selfie"]
        front = body["front"]
        back = body['back']
        guest_id = body["guest_id"]

        result, score = compare_faces_from_s3(
            BUCKET_NAME, selfie, BUCKET_NAME, front
        )
        guests.update_item(
            Key={
                "booking_id": token["booking_id"],
                "guest_id": guest_id
            },
            UpdateExpression="SET verified = :val, #front = :front, #back = :back, #selfie = :selfie",
            ExpressionAttributeNames={
                "#front": "front",
                "#back": "back",
                "#selfie": "selfie"
            },
            ExpressionAttributeValues={
                ":val": result,
                ":front": front,
                ":back": back,
                ":selfie": selfie
            },
            ReturnValues="UPDATED_NEW",
        )


        return generate_response(201, {"resul": result, "score": score})

    except Exception as e:
        return generate_response(
            500, {"message": "Failed to add guest", "error": str(e)}
        )


def get_image_bytes(bucket, key):
    response = s3_client.get_object(Bucket=bucket, Key=key)
    return response["Body"].read()


def compare_faces_from_s3(
    source_bucket, source_key, target_bucket, target_key, threshold=90
):
    try:
        source_bytes = get_image_bytes(source_bucket, source_key)
        target_bytes = get_image_bytes(target_bucket, target_key)

        response = rekognition_client.compare_faces(
            SourceImage={"Bytes": source_bytes},
            TargetImage={"Bytes": target_bytes},
            SimilarityThreshold=threshold,
        )

        matches = response.get("FaceMatches", [])
        if matches:
            similarity = matches[0]["Similarity"]
            print(f"✅ Match found! Similarity: {similarity:.2f}%")
            return True, similarity
        else:
            print("❌ No match found.")
            return False, 0

    except Exception as e:
        print(e)
        return False, 0


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


def validate_guest_data(body):
    errors = {}

    # Basic required fields
    if "stato_nascita_code" not in body:
        errors["stato_nascita_code"] = "Country of birth is required"
    if "tipo_allogiato_code" not in body:
        errors["tipo_allogiato_code"] = "Type of guest is required"

    if errors:
        return False, errors

    # Determine required fields based on country and guest type
    required  = [
        'tipo_allogiato_code',
        "nome","cognome",'data_nascita', 'sesso', 
        'stato_nascita','stato_nascita_code',
        
        'cittadinanza','cittadinanza_code',
        
    ]
    missing_fields = [ item for item in required if item not in body or body[item] in [None, ""]]
    if missing_fields:
        errors.update({field: f"{field.replace('_', ' ').capitalize()} is required" for field in missing_fields})
        return False, errors
    if body["stato_nascita_code"] == "100000100":
        required += [
            'comune_nascita',
            "comune_nascita_code",
            "provincia_nascita"
        ]
        

    if body["tipo_allogiato_code"] in ["16","17",'18']: 
        required +=[
            'tipo_documento',
            'tipo_documento_code',
            'numero_documento',
            'luogo_rilascio_paese',
           'luogo_rilascio_paese_code'
        ]

    # Check for missing fields
    for field in required:
        if field not in body or body[field] in [None, ""]:
            errors[field] = f"{field.replace('_', ' ').capitalize()} is required"

    if errors:
        return False, errors

    return True, {}


def analyze_document(images):
    model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"

    images.append(
        {
            "type": "text",
            "text": """
                        You're a document parser. Your task is to extract the following fields from the image of an identity document. Return the result as a JSON object with each field clearly filled, or `null` if not available.

Fields to extract:


- nome (nome della persona)
- cognome (cognome della persone)
- data_nascita (format: YYYY-MM-DD)
- sesso (1 for male and 2 for female)
- comune_nascita
- comune_nascita_code (italian abbreviation for  comune_nascita, ES for foreigners)
- provincia_nascita (sigla of the province of birth, e.g., RM for Rome)
- stato_nascita
- stato_nascita_code (ISO 3166-1 alpha-2, e.g., IT, FR)
- cittadinanza (full italian country name like ITALIA POLONIA,CANADA)
- tipo_documento (e.g., "Passaporto", "Carta d'identità")
- tipo_documento_code (e.g., "P" for passport, "ID" for ID card)
- numero_documento
- luogo_rilascio_paese (name of the country where the document was issued)
- luogo_rilascio_provincia (sigle of the province where the document was issued, only for italian documents)
- luogo_rilascio_comune (name of the city where the document was issued, only for italian documents)

Only return the structured JSON output. Do not explain your answer.

All the fiels should be compliant with the data required for the italian website Allogiati Web.

""",
        }
    )
    request = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 512,
        "temperature": 0.8,
        "messages": [{"role": "user", "content": images}],
    }

    request = json.dumps(request)
    response = client.invoke_model(modelId=model_id, body=request)
    body = json.loads(response["body"].read().decode())
    message = body["content"][0]["text"]
    return message


def post_process_data(data):
    print(data)
    tipo_documento_object = get_document_type_code(data["tipo_documento"])
    data["tipo_documento"] = tipo_documento_object["descrizione"]
    data["tipo_documento_code"] = tipo_documento_object["codice"]
    data["tipo_documento_score"] = tipo_documento_object["similarity"]

    # Paese di nascita

    stato_nascita_object = get_stato_nascita_code(data["stato_nascita"])
    print(f"Identified stato nascita: {stato_nascita_object}")
    data["stato_nascita"] = stato_nascita_object["descrizione"]
    data["stato_nascita_code"] = stato_nascita_object["codice"]
    data["stato_nascita_score"] = stato_nascita_object["similarity"]
    # Cittadinanza
    cittadinanza_object = get_stato_nascita_code(data["cittadinanza"])
    print(f"Identified cittadinanza_object: {cittadinanza_object}")
    data["cittadinanza"] = cittadinanza_object["descrizione"]
    data["cittadinanza_code"] = cittadinanza_object["codice"]
    data["cittadinanza_score"] = cittadinanza_object["similarity"]

    if data["stato_nascita_code"] == "100000100":
        data["foreigner"] = False
        # Process provincia nascita
        provincia_nascita = get_provincia_code(data["provincia_nascita"])
        print(f"Identified provincia nascita: {provincia_nascita}")
        if provincia_nascita:
            data["provincia_nascita"] = provincia_nascita

            comune_nascita_object = get_comune_nascita_code(
                provincia_nascita, data["comune_nascita"]
            )
            if comune_nascita_object:
                print(f"Identified comune nascita: {comune_nascita_object['codice']}")
                data["comune_nascita"] = comune_nascita_object[
                    "descrizione"
                ]
                data["comune_nascita_code"] = comune_nascita_object["codice"]
                data["comune_nascita_score"] = comune_nascita_object["similarity"]
            else:
                data["comune_nascita"] = None
                data["comune_nascita_codice"] = None
                data["comune_nascita_score"] = 0

            

        else:
            data["provincia_nascita"] = None
            data["provincia_nascita"] = None
            data["provincia_nascita_score"] = 0
            

    else:
        data["foreigner"] = True


    luogo_rilascio_paese_object = get_stato_nascita_code(
                 data["luogo_rilascio_paese"]
            )
    if luogo_rilascio_paese_object:
        data['luogo_rilascio_paese_code'] = luogo_rilascio_paese_object["codice"]
        data["luogo_rilascio_paese"] = luogo_rilascio_paese_object["descrizione"]
        data["luogo_rilascio_paese_score"] = luogo_rilascio_paese_object["similarity"]
        print(f"Identified luogo rilascio paese: {luogo_rilascio_paese_object['codice']}")
        if luogo_rilascio_paese_object["codice"] == "100000100":
            
            luogo_rilascio_provincia = get_provincia_code(
                data["luogo_rilascio_provincia"])
            if luogo_rilascio_provincia:
                print(f"Identified luogo rilascio provincia: {luogo_rilascio_provincia}")
                data["luogo_rilascio_provincia"] = luogo_rilascio_provincia
                
                luogo_rilascio_comune= get_comune_nascita_code(
                    luogo_rilascio_provincia,
                    data["luogo_rilascio_comune"],
                )
                if luogo_rilascio_comune:
                    print(f"Identified luogo rilascio comune: {luogo_rilascio_comune['codice']}")
                    data['luogo_rilascio_comune_code'] = luogo_rilascio_comune["codice"]
                    data["luogo_rilascio_comune"] = luogo_rilascio_comune["descrizione"]
                    data["luogo_rilascio_comune_score"] = luogo_rilascio_comune["similarity"]
                else:
                    print("No matching comune found for luogo rilascio comune")
                    data['luogo_rilascio_comune_code'] = ''
                    data["luogo_rilascio_comune"] = ''
                    data["luogo_rilascio_comune_score"] = ''
            else:
                print("No matching provincia found for luogo rilascio provincia")
                data['luogo_rilascio_comune_code'] = ''
                data["luogo_rilascio_comune"] = ''
                data["luogo_rilascio_comune_score"] = ''
                
        else:
            print("Non-Italian document, setting luogo rilascio provincia and comune to empty")
            data['luogo_rilascio_provincia_code'] = ''
            data["luogo_rilascio_provincia"] = ''
            data["luogo_rilascio_provincia_score"] = ''
            data['luogo_rilascio_comune_code'] = ''
            data["luogo_rilascio_comune"] = ''
            data["luogo_rilascio_comune_score"] = ''
            
    else:
        data['luogo_rilascio_paese_code'] = ''
        data["luogo_rilascio_paese"] = ''
        data["luogo_rilascio_paese_score"] =''
        data['luogo_rilascio_provincia_code'] = ''
        data["luogo_rilascio_provincia"] = ''
        data["luogo_rilascio_provincia_score"] = ''
        data['luogo_rilascio_comune_code'] = ''
        data["luogo_rilascio_comune"] = ''
        data["luogo_rilascio_comune_score"] = ''

    print(data)
    return data


def get_provincia_code(provincia):
    try:
        code = provincia.strip().upper()
        # Load the CSV file from S3 into a pandas DataFrame
        response = s3_client.get_object(
            Bucket="airbnb-allogiati-web-files", Key="province.csv"
        )
        content = response["Body"].read().decode("utf-8")

        # Assume the code is in the first column — adjust `usecols` or column name if needed
        df = pd.read_csv(io.StringIO(content), header=None)

        # Check if the code exists
        if code in df.iloc[:, 0].astype(str).str.strip().str.upper().values:
            return code
        else:
            return None

    except Exception as e:
        print(f"Error checking provincia code: {e}")
        return None


def get_comune_nascita_code(
    provincia_code,
    comune_nascita,
    bucket="airbnb-allogiati-web-files",
    key="comuni.csv",
):
    provincia_code = provincia_code.strip().upper() if provincia_code else None
    comune_nascita = comune_nascita.strip().lower()

    try:
        # Load CSV from S3
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response["Body"].read().decode("utf-8")
        df = pd.read_csv(io.StringIO(content), delimiter=",", dtype=str)

        # Standardize columns
        df = df[["Codice", "Descrizione", "Provincia"]]
        df["Provincia"] = df["Provincia"].str.strip().str.upper()
        df["Descrizione"] = df["Descrizione"].str.strip()

        # Filter by Provincia
        if provincia_code:
            filtered_df = df[df["Provincia"] == provincia_code]
        else:
            filtered_df = df
        if filtered_df.empty:
            print(f"No comuni found for provincia code: {provincia_code}")
            return None

        # Compute similarity
        filtered_df["similarity"] = (
            filtered_df["Descrizione"]
            .str.lower()
            .apply(lambda x: difflib.SequenceMatcher(None, x, comune_nascita).ratio())
        )

        # Get best match
        best_match = filtered_df.sort_values(by="similarity", ascending=False).iloc[0]

        return {
            "descrizione": best_match["Descrizione"],
            "codice": best_match["Codice"],
            "similarity": best_match["similarity"],
        }

    except Exception as e:
        print(f"Error processing comune nascita: {e}")
        return None


def get_stato_nascita_code(
    stato_nascita, bucket="airbnb-allogiati-web-files", key="stati.csv"
):
    stato_nascita = stato_nascita.strip().lower()

    try:
        # Load CSV from S3
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response["Body"].read().decode("utf-8")
        df = pd.read_csv(io.StringIO(content), delimiter=",", dtype=str)

        # Clean column values
        df["Descrizione"] = df["Descrizione"].str.strip().str.lower()
        df["Codice"] = df["Codice"].str.strip()

        # Compute similarity
        df["similarity"] = df["Descrizione"].apply(
            lambda x: difflib.SequenceMatcher(None, x, stato_nascita).ratio()
        )

        best_match = df.sort_values(by="similarity", ascending=False).iloc[0]

        # Optional threshold to avoid bad matches

        return {
            "descrizione": best_match["Descrizione"].title(),
            "codice": best_match["Codice"],
            "similarity": best_match["similarity"],
        }

    except Exception as e:
        print(f"Error processing stato_nascita: {e}")
        return None


def get_document_type_code(
    typo_documento, bucket="airbnb-allogiati-web-files", key="documenti.csv"
):
    typo_documento = typo_documento.strip().lower()

    try:
        # Load CSV from S3
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response["Body"].read().decode("utf-8")
        df = pd.read_csv(io.StringIO(content), delimiter=",", dtype=str)

        # Clean column values
        df["Descrizione"] = df["Descrizione"].str.strip().str.lower()
        df["Codice"] = df["Codice"].str.strip()

        # Compute similarity
        df["similarity"] = df["Descrizione"].apply(
            lambda x: difflib.SequenceMatcher(None, x, typo_documento).ratio()
        )

        best_match = df.sort_values(by="similarity", ascending=False).iloc[0]

        # Optional threshold to avoid bad matches

        return {
            "descrizione": best_match["Descrizione"].title(),
            "codice": best_match["Codice"],
            "similarity": best_match["similarity"],
        }

    except Exception as e:
        print(f"Error processing stato_nascita: {e}")
        return None

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