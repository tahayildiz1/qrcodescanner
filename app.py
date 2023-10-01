from flask import Flask, render_template, request, Response, jsonify, redirect, url_for
from functools import wraps
from pyzbar.pyzbar import decode
import cv2
import numpy as np
import requests
import mysql.connector
import flask_mail
import requests
from telegram import Bot
from telegram.constants import ParseMode
from db_config import DB_CONFIG 
from config import VIRUSTOTAL_API_KEY
from mail_config import MAIL_CONFIG
from ip_info import IPINFO_API_KEY
from datetime import datetime
from flask_mail import Mail
from flask_mail import Message

app = Flask(__name__)

mail = Mail(app)

bot = Bot(token=" ")

# Define a simple username and password (change these)
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

        # Define the SQL query to search for URLs based on the search_query
        query = "SELECT * FROM scan_results WHERE url LIKE %s"
        # Use % to search for URLs containing the search_query
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

def get_user_public_ip():
    try:
        # Check if the X-Forwarded-For header is present
        if 'X-Forwarded-For' in request.headers:
            # The header may contain a comma-separated list of IP addresses;
            # the leftmost IP address is usually the client's public IP
            x_forwarded_for = request.headers['X-Forwarded-For']
            user_public_ip = x_forwarded_for.split(',')[0].strip()
            return user_public_ip
        else:
            # If the header is not present, fall back to request.remote_addr
            return request.remote_addr
    except Exception as e:
        print("Error getting user's public IP:", str(e))
        return 'Unknown'



@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return "No file part"

    file = request.files['file']
    if file.filename == '':
        return "No selected file"

    # Get the user's IP address and city using ipinfo.io
    user_ip = request.remote_addr  # Get the user's IP address
    ip_info_url = f"https://ipinfo.io/{user_ip}/json?token={IPINFO_API_KEY}"  # Use the API key
    response = requests.get(ip_info_url)
    ip_info = response.json()
    user_city = ip_info.get('city', 'Unknown')  # Get the user's city or default to 'Unknown'

    # Read the uploaded image
    image = cv2.imdecode(np.fromstring(file.read(), np.uint8), cv2.IMREAD_UNCHANGED)

    # Decode QR codes in the image
    decoded_objects = decode(image)

    if decoded_objects:
        urls = [obj.data.decode("utf-8") for obj in decoded_objects]

        # Create a list of results including IP address and city
        results = []
        for url in urls:
            result = check_single_url_with_virustotal(url)
            result['user_ip'] = user_ip  # Add the user's IP address to the result
            result['user_city'] = user_city  # Add the user's city to the result
            results.append(result)

        # Save the results to the database
        save_results_to_mysql(results)

        # Debug: Print scanned URLs
        print("Scanned URLs:", urls)

        # Render a template with the scan results
        return render_template('results.html', results=results)
    else:
        return "No QR code found in the image"

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form.get('url')

    if url:
        # Get the user's public IP address
        user_ip = get_user_public_ip()

        # Get the user's city using ipinfo.io
        ip_info_url = f"https://ipinfo.io/{user_ip}/json?token={IPINFO_API_KEY}"
        response = requests.get(ip_info_url)
        ip_info = response.json()
        user_city = ip_info.get('city', 'Unknown')

        result = check_single_url_with_virustotal(url)
        result['user_ip'] = user_ip
        result['user_city'] = user_city

        # Save the single result to the database
        save_results_to_mysql([result])
        save_ip_results_to_mysql(user_ip, user_city)

        return render_template('check_url.html', result=result)
    else:
        return "No URL provided."

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/thanks')
def thanks():
    return render_template('thanks.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        chat_id = " "  
        notification_message = f"Name: {name}\nEmail: {email}\nMessage:\n{message}"

        async def send_message():
            await bot.send_message(chat_id=chat_id, text=notification_message, parse_mode=ParseMode.MARKDOWN)

        import asyncio
        asyncio.run(send_message())

        return redirect(url_for('thanks'))

    # Render the contact form page for GET requests
    return render_template('contact.html')



def check_single_url_with_virustotal(url):
    # Debug: Print URL being checked
    print("Checking URL:", url)

    # Perform the API request to check the URL status here
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

        # Debug: Print URL being checked
        print("Checking URL:", url)

        # Use the current date and time instead of VirusTotal's scan date
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check the response from VirusTotal for malicious indicators
        if json_response.get('positives', 0) > 0:
            status = 'Malicious'
        else:
            status = 'Not Malicious'

        result = {
            'url': url,
            'status': status,
            'scan_date': scan_date  # Use the current date and time
        }

        results.append(result)

    return results

def save_results_to_mysql(results):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        for result in results:
            # Check if the URL already exists in the database
            query = "SELECT * FROM scan_results WHERE url = %s"
            cursor.execute(query, (result['url'],))
            existing_result = cursor.fetchone()

            if not existing_result:
                # URL does not exist, so insert it
                insert_query = "INSERT INTO scan_results (url, status, scan_date) VALUES (%s, %s, %s)"
                values = (result['url'], result['status'], result['scan_date'])
                cursor.execute(insert_query, values)

        conn.commit()
        cursor.close()
        conn.close()

    except mysql.connector.Error as err:
        print(f"MySQL Error: {err}")

def save_ip_results_to_mysql(ip_address, city):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Check if the IP address already exists in the database
        query = "SELECT * FROM ip_results WHERE ip_address = %s"
        cursor.execute(query, (ip_address,))
        existing_result = cursor.fetchone()

        if not existing_result:
            # IP address does not exist, so insert it
            insert_query = "INSERT INTO ip_results (ip_address, city) VALUES (%s, %s)"
            values = (ip_address, city)
            cursor.execute(insert_query, values)

            # Add print statements to debug
            print(f"Inserted IP Address: {ip_address}")
            print(f"Inserted City: {city}")

        conn.commit()
        cursor.close()
        conn.close()

    except mysql.connector.Error as err:
        print(f"MySQL Error: {err}")

        # Print additional information about the IP address and city
        print(f"IP Address: {ip_address}")
        print(f"City: {city}")

@app.route('/admin')
@requires_admin_auth
def admin():
    # Fetch the scanned URLs (you can query your database here)
    results = fetch_scanned_urls()
    return render_template('admin.html', results=results)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html'), 404


@app.route('/admin/search', methods=['GET'])
@requires_admin_auth
def search():
    search_query = request.args.get('search_query', '')

    # Call the search_urls function to perform the search
    results = search_urls(search_query)
    
    return render_template('admin.html', search_results=results, search_query=search_query)

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=False,port=5000)
