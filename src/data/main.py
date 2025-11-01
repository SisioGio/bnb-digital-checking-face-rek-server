
import csv
import json
import os

def convert_csv_to_json(csv_file_path, json_file_path, fieldnames=None):
    data = []

    with open(csv_file_path, mode='r', encoding='utf-8-sig') as csv_file:
        reader = csv.DictReader(csv_file) if not fieldnames else csv.DictReader(csv_file, fieldnames=fieldnames)
        for row in reader:
            # Strip leading/trailing spaces and filter out empty keys
            clean_row = {k.strip(): v.strip() for k, v in row.items() if k and v}
            data.append(clean_row)

    with open(json_file_path, mode='w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=2, ensure_ascii=False)

    print(f"✅ Converted: {csv_file_path} → {json_file_path}")


json_file_path = r'C:\Users\Alessio\Documents\Projects\airbnb\src\data\comuni.json'
with open(json_file_path, mode='r', encoding='utf-8') as json_file:
        comuni = json.load(json_file)
province = sorted({comune['Provincia'] for comune in comuni})  # distinct and sorted
province.append('ES')
print(province)
        
        