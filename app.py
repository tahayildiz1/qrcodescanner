from flask import Flask, render_template, request
from pyzbar.pyzbar import decode
import cv2
import numpy as np
import requests
import mysql.connector
from db_config import DB_CONFIG  # Import database credentials
from config import VIRUSTOTAL_API_KEY  # Import the VirusTotal API key from config.py

app = Flask(__name__)

# ... (Other imports and app initialization)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return "No file part"

    file = request.files['file']
    if file.filename == '':
        return "No selected file"

    # Read the uploaded image
    image = cv2.imdecode(np.fromstring(file.read(), np.uint8), cv2.IMREAD_UNCHANGED)

    # Decode QR codes in the image
    decoded_objects = decode(image)

    if decoded_objects:
        urls = [obj.data.decode("utf-8") for obj in decoded_objects]
        results = check_url_with_virustotal(urls)
        save_results_to_mysql(results)

        # Render a template with the scan results
        return render_template('results.html', results=results)
    else:
        return "No QR code found in the image"

def check_url_with_virustotal(urls):
    results = []

    for url in urls:
        params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'resource': url
        }
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        json_response = response.json()

        # Check the response from VirusTotal for malicious indicators
        if json_response.get('positives', 0) > 0:
            status = 'Malicious'
        else:
            status = 'Not Malicious'

        result = {
            'url': url,
            'status': status,
            'scan_date': json_response.get('scan_date')
        }

        results.append(result)

    return results

def save_results_to_mysql(results):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        for result in results:
            query = "INSERT INTO scan_results (url, status, scan_date) VALUES (%s, %s, %s)"
            values = (result['url'], result['status'], result['scan_date'])
            cursor.execute(query, values)

        conn.commit()
        cursor.close()
        conn.close()

    except mysql.connector.Error as err:
        print(f"MySQL Error: {err}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
