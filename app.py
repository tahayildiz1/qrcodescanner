from flask import Flask, render_template, request, Response, jsonify, redirect, url_for
from functools import wraps
from pyzbar.pyzbar import decode
import cv2
import numpy as np
import requests
import mysql.connector
import flask_mail
from db_config import DB_CONFIG 
from config import VIRUSTOTAL_API_KEY
from mail_config import MAIL_CONFIG
from datetime import datetime
from flask_mail import Mail
from flask_mail import Message


app = Flask(__name__)

mail = Mail(app)

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

def search_urls(search_query):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM scan_results WHERE url LIKE %s"
        search_query = f"%{search_query}%"
        cursor.execute(query, (search_query,))

        results = cursor.fetchall()

        cursor.close()
        conn.close()

        return results

    except mysql.connector.Error as err:
        print(f"MySQL Error: {err}")
        return []

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

    decoded_objects = decode(image)

    if decoded_objects:
        urls = [obj.data.decode("utf-8") for obj in decoded_objects]
        results = check_url_with_virustotal(urls)
        save_results_to_mysql(results)

        print("Scanned URLs:", urls)

        return render_template('results.html', results=results)
    else:
        return "No QR code found in the image"

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form.get('url')

    if url:
        result = check_single_url_with_virustotal(url)
        save_results_to_mysql([result])
        return render_template('url_status.html', result=result)
    else:
        return "No URL provided."

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        msg = Message(
            'New Contact Form Submission',
            sender=MAIL_CONFIG['MAIL_USERNAME'],
            recipients=[' ']
        )
        msg.body = f'Name: {name}\nEmail: {email}\nMessage:\n{message}'

        mail.send(msg)

        # Optionally, you can redirect to a thank-you page
        #return redirect(url_for('thank_you'))

    return render_template('contact.html')



def check_single_url_with_virustotal(url):
    print("Checking URL:", url)

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
        'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Use the current date and time
    }

    return result

def check_url_with_virustotal(urls):
    results = []

    for url in urls:
        params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'resource': url
        }
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        json_response = response.json()

        print("Checking URL:", url)

        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if json_response.get('positives', 0) > 0:
            status = 'Malicious'
        else:
            status = 'Not Malicious'

        result = {
            'url': url,
            'status': status,
            'scan_date': scan_date
        }

        results.append(result)

    return results

def save_results_to_mysql(results):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        for result in results:
            query = "SELECT * FROM scan_results WHERE url = %s"
            cursor.execute(query, (result['url'],))
            existing_result = cursor.fetchone()

            if not existing_result:
                insert_query = "INSERT INTO scan_results (url, status, scan_date) VALUES (%s, %s, %s)"
                values = (result['url'], result['status'], result['scan_date'])
                cursor.execute(insert_query, values)

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

@app.route('/admin/search', methods=['GET'])
@requires_admin_auth
def search():
    search_query = request.args.get('search_query', '')

    results = search_urls(search_query)
    
    return render_template('admin.html', search_results=results, search_query=search_query)

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=False,port=5000)
