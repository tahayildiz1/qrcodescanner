from flask import Flask, render_template, request, Response, jsonify, redirect, url_for
from functools import wraps
from pyzbar.pyzbar import decode
import cv2
import numpy as np
import requests
import mysql.connector
from db_config import DB_CONFIG  
from config import VIRUSTOTAL_API_KEY 

app = Flask(__name__)


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

def check_auth(username, password):
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def authenticate():
    return Response('Authentication required.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.before_request
def before_request():
    if request.endpoint == "admin":
        if not request.authorization or not check_auth(request.authorization.username, request.authorization.password):
            return authenticate()

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

    image = cv2.imdecode(np.fromstring(file.read(), np.uint8), cv2.IMREAD_UNCHANGED)

    decoded_objects = decode(image)

    if decoded_objects:
        urls = [obj.data.decode("utf-8") for obj in decoded_objects]
        results = check_url_with_virustotal(urls)
        save_results_to_mysql(results)

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
            query = "SELECT id FROM scan_results WHERE url = %s"
            cursor.execute(query, (result['url'],))
            existing_record = cursor.fetchone()

            if not existing_record:
                insert_query = "INSERT INTO scan_results (url, status, scan_date) VALUES (%s, %s, %s)"
                insert_values = (result['url'], result['status'], result['scan_date'])
                cursor.execute(insert_query, insert_values)

        conn.commit()
        cursor.close()
        conn.close()

    except mysql.connector.Error as err:
        print(f"MySQL Error: {err}")


@app.route('/admin')
@requires_admin_auth
def admin():
    results = fetch_scanned_urls()
    return render_template('admin.html', results=results)

def fetch_scanned_urls():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        query = "SELECT url, status, scan_date FROM scan_results"
        cursor.execute(query)

        rows = cursor.fetchall()

        results = [{'url': row[0], 'status': row[1], 'scan_date': row[2]} for row in rows]

        cursor.close()
        conn.close()

        return results

    except mysql.connector.Error as err:
        print(f"MySQL Error: {err}")
        return []


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
