
import boto3

import base64
import json
import pandas as pd
import io
import difflib

client = boto3.client("bedrock-runtime")
s3 = boto3.client('s3')
def analyze_document(images):
    model_id = 'anthropic.claude-3-5-sonnet-20240620-v1:0'
    prompt="Return all data from this document",
    
    images.append(  {
                        'type':'text',
                        'text':"""
                        You're a document parser. Your task is to extract the following fields from the image of an identity document. Return the result as a JSON object with each field clearly filled, or `null` if not available.

Fields to extract:

- guest_type (either "1" for Italian citizen or "2" for foreign guest)
- name
- last_name
- birthdate (format: YYYY-MM-DD)
- gender (M/F)
- comune_nascita
- comune_nascita_code (italian abbreviation for  comune_nascita, ES for foreigners)
- provincia_nascita
- stato_nascita
- stato_nascita_code (ISO 3166-1 alpha-2, e.g., IT, FR)
- cittadinanza (full italian country name like ITALIA POLONIA,CANADA)
- tipo_documento (e.g., "Passaporto", "Carta d'identità")
- tipo_documento_code (e.g., "P" for passport, "ID" for ID card)
- numero_documento
- luogo_rilascio
- foreigner (true if stato_nascita is not Italy)

Only return the structured JSON output. Do not explain your answer.

All the fiels should be compliant with the data required for the italian website Allogiati Web.

"""
                    })
    request = {
        'anthropic_version':'bedrock-2023-05-31',
        'max_tokens':512,
        'temperature':0.8,
        'messages':[
            {
                "role":"user",
                "content":images
            }
        ]
    }
    
    request=json.dumps(request)
    response = client.invoke_model(modelId=model_id,body=request)
    body=json.loads(response['body'].read().decode())
    message = body['content'][0]['text']
    return message


def extract_data(event):
    images_data = [
        {
            'key':'7bdc1b54-4baa-42e6-b1bd-a673d842351f.jpg',
            'name':'back',
            'type':'image/jpg'
        },
        {
            'name':'front',
            'type':'image/jpg',
            'key':"e5e26390-bedf-4ae3-809f-c1098ffbaa00.jpg"
        }
    ]


    content = []
    s3_client = boto3.client('s3')
    for image in images_data:
        s3_response = s3_client.get_object(Bucket='document-processor-upload-files-21342512924',Key=image['key'])
        image_bytes = s3_response['Body'].read()
        encoded_image = base64.b64encode(image_bytes).decode('utf-8')
        content.append({'type':'image','source':{'type':'base64','media_type':'image/png','data':encoded_image}})

    response = analyze_document(content)


def post_process_data():
    data={
            "guest_type": "1",
            "name": "ALESSIO MASSIMO",
            "last_name": "GIOVANNINI",
            "birthdate": "1998-03-17",
            "gender": "M",
            "comune_nascita": "BRACCIANO",
            "comune_nascita_code": None,
            "provincia_nascita": "RM",
            "stato_nascita": "ITALIA",
            "stato_nascita_code": "IT",
            "cittadinanza": "ITALIA",
            "tipo_documento": "Carta d'identità",
            "tipo_documento_code": "ID",
            "numero_documento": "CA57822AF",
            "luogo_rilascio": "VITERBO",
            "foreigner": False    
    }
    
    tipo_documento_object = get_document_type_code(data['tipo_documento'])
    data['tipo_document_descrizione'] = tipo_documento_object['descrizione']
    data['tipo_document_codice'] = tipo_documento_object['codice']
    data['tipo_document_score'] = tipo_documento_object['similarity']
    
    
    # Paese di nascita
    
    paese_nascita_object = get_stato_nascita_code(data['stato_nascita'])
    print(f"Identified paese nascita: {paese_nascita_object}")
    data['paese_nascita_descrizione'] = paese_nascita_object['descrizione']
    data['paese_nascita_codice'] = paese_nascita_object['codice']
    data['paese_nascita_score'] = paese_nascita_object['similarity']
    
    if data['paese_nascita_codice'] =='100000100':
        data['foreigner'] = False
        # Process provincia nascita
        provincia_nascita = get_provincia_code(data['provincia_nascita'])
        print(f"Identified provincia nascita: {provincia_nascita}")
        if  provincia_nascita:
            
            data['provincia_nascita_codice'] = provincia_nascita
            
            comune_nascita_object = get_comune_nascita_code(provincia_nascita,data['comune_nascita'])
            if comune_nascita_object:
                data['comune_nascita_descrizione'] = comune_nascita_object['descrizione']
                data['comune_nascita_codice'] = comune_nascita_object['codice']
                data['comune_nascita_score'] = comune_nascita_object['similarity']
            else:
                data['comune_nascita_descrizione'] = None
                data['comune_nascita_codice'] = None
                data['comune_nascita_score'] = 0
        else:
            data['provincia_nascita_descrizione'] = None
            data['provincia_nascita_codice'] = None
            data['provincia_nascita_score'] = 0
            
        
        
        
        
    else:
        data['foreigner']=True
        # Assign luogo rilascio = pease nascita
        data['luogo_rilascio_codice'] = data['paese_nascita_codice']
        data['luogo_rilascio_descrizione'] = data['paese_nascita_descrizione']
        data['luogo_rilascio_score'] = data['paese_nascita_score']
        
    print(data)
    return data
    
def get_provincia_code(provincia):
   
    

    try:
        code = provincia.strip().upper()
        # Load the CSV file from S3 into a pandas DataFrame
        response = s3.get_object(
            Bucket='airbnb-allogiati-web-files',
            Key='province.csv'
        )
        content = response['Body'].read().decode('utf-8')

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
    
    
def get_comune_nascita_code(provincia_code, comune_nascita, bucket='airbnb-allogiati-web-files', key='comuni.csv'):

    provincia_code = provincia_code.strip().upper()
    comune_nascita = comune_nascita.strip().lower()

    try:
        # Load CSV from S3
        response = s3.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read().decode('utf-8')
        df = pd.read_csv(io.StringIO(content), delimiter=",", dtype=str)

        # Standardize columns
        df = df[['Codice', 'Descrizione', 'Provincia']]
        df['Provincia'] = df['Provincia'].str.strip().str.upper()
        df['Descrizione'] = df['Descrizione'].str.strip()

        # Filter by Provincia
        filtered_df = df[df['Provincia'] == provincia_code]

        if filtered_df.empty:
            print(f"No comuni found for provincia code: {provincia_code}")
            return None

        # Compute similarity
        filtered_df['similarity'] = filtered_df['Descrizione'].str.lower().apply(
            lambda x: difflib.SequenceMatcher(None, x, comune_nascita).ratio()
        )

        # Get best match
        best_match = filtered_df.sort_values(by='similarity', ascending=False).iloc[0]

        return {
            'descrizione': best_match['Descrizione'],
            'codice': best_match['Codice'],
            'similarity': best_match['similarity']
        }

    except Exception as e:
        print(f"Error processing comune nascita: {e}")
        return None


def get_stato_nascita_code(stato_nascita, bucket='airbnb-allogiati-web-files', key='stati.csv'):
    stato_nascita = stato_nascita.strip().lower()

    try:
        # Load CSV from S3
        response = s3.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read().decode('utf-8')
        df = pd.read_csv(io.StringIO(content), delimiter=",", dtype=str)

        # Clean column values
        df['Descrizione'] = df['Descrizione'].str.strip().str.lower()
        df['Codice'] = df['Codice'].str.strip()

        # Compute similarity
        df['similarity'] = df['Descrizione'].apply(
            lambda x: difflib.SequenceMatcher(None, x, stato_nascita).ratio()
        )

        best_match = df.sort_values(by='similarity', ascending=False).iloc[0]

        # Optional threshold to avoid bad matches
  

        return {
            'descrizione': best_match['Descrizione'].title(),
            'codice': best_match['Codice'],
            'similarity': best_match['similarity']
        }

    except Exception as e:
        print(f"Error processing stato_nascita: {e}")
        return None  


def get_document_type_code(typo_documento, bucket='airbnb-allogiati-web-files', key='documenti.csv'):
    typo_documento = typo_documento.strip().lower()

    try:
        # Load CSV from S3
        response = s3.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read().decode('utf-8')
        df = pd.read_csv(io.StringIO(content), delimiter=",", dtype=str)

        # Clean column values
        df['Descrizione'] = df['Descrizione'].str.strip().str.lower()
        df['Codice'] = df['Codice'].str.strip()

        # Compute similarity
        df['similarity'] = df['Descrizione'].apply(
            lambda x: difflib.SequenceMatcher(None, x, typo_documento).ratio()
        )

        best_match = df.sort_values(by='similarity', ascending=False).iloc[0]

        # Optional threshold to avoid bad matches
  

        return {
            'descrizione': best_match['Descrizione'].title(),
            'codice': best_match['Codice'],
            'similarity': best_match['similarity']
        }

    except Exception as e:
        print(f"Error processing stato_nascita: {e}")
        return None  
 

 
rekognition_client = boto3.client('rekognition')

response = rekognition_client.compare_faces(
    SourceImage={'Bytes': open(r"C:\Users\Alessio\Downloads\IMG_9149.jpeg", 'rb').read()},
    TargetImage={'Bytes': open(r"C:\Users\Alessio\Pictures\Camera Roll\WIN_20250602_18_22_24_Pro.jpg", 'rb').read()},
    SimilarityThreshold=90
)

matches = response['FaceMatches']
if matches:
    similarity = matches[0]['Similarity']
    print(f"Match found! Similarity: {similarity}%")
else:
    print("No match found.")