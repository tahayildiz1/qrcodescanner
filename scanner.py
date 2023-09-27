import cv2
import requests
import json
import subprocess
import csv

# Read API keys from the JSON file
with open('api_keys.json', 'r') as keys_file:
    api_keys = json.load(keys_file)

API_KEY = api_keys.get("VIRUSTOTAL_API_KEY", "Default_VirusTotal_API_KEY")
IPINFO_API_KEY = api_keys.get("IPINFO_API_KEY", "Default_IPINFO_API_KEY")

def check_link_with_virustotal(url):
    params = {'apikey': API_KEY, 'resource': url}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    result = response.json()
    return result

def get_public_ip():
    try:
        # Use curl to get public IP address from ifconfig.io
        ip_address = subprocess.check_output(["curl", "ifconfig.io"], universal_newlines=True).strip()
        return ip_address
    except subprocess.CalledProcessError:
        return None

def get_ip_location(ip_address):
    ipinfo_response = requests.get(f"http://ipinfo.io/{ip_address}?token={IPINFO_API_KEY}")
    ipinfo_data = json.loads(ipinfo_response.text)
    
    # Get various IPinfo data
    country = ipinfo_data.get('country')
    city = ipinfo_data.get('city')
    
    return {
        'Location_Country': country,
        'Location_City': city,
    }

def save_to_csv(data):
    with open('scan_results.csv', mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=data.keys())
        if file.tell() == 0:
            writer.writeheader()
        writer.writerow(data)

cap = cv2.VideoCapture(0)

while True:
    ret, frame = cap.read()
    if not ret:
        continue

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    qr_code_detector = cv2.QRCodeDetector()
    retval, decoded_info, points, _ = qr_code_detector.detectAndDecodeMulti(gray)

    if retval:
        print("Decoded QR Code:", decoded_info)
        virustotal_result = check_link_with_virustotal(decoded_info)

        ip_address = get_public_ip()

        if ip_address:
            ipinfo_location = get_ip_location(ip_address)
            
            if isinstance(virustotal_result, dict):
                if virustotal_result.get('response_code', -1) == 1:
                    scan_count = virustotal_result.get('total', 0)
                    if virustotal_result.get('positives', 0) == 0:
                        scan_result = 'Safe'
                    else:
                        scan_result = 'Unsafe'
                        print(f"Gescannte Antiviren-Scanner: {scan_count}")
                        print("Erkannte Bedrohungen:")
                        for scan, info in virustotal_result.get('scans', {}).items():
                            if info.get('detected'):
                                print(f"{scan}: {info.get('result', 'Keine Informationen')}")
                else:
                    scan_result = 'Unknown'
                    print("Der Link konnte nicht überprüft werden.")
            else:
                scan_result = 'Error'
                print("Fehler bei der API-Antwort.")
            
            scan_data = {
                'Decoded_QR_Code': decoded_info,
                **ipinfo_location,
                'Scan_Result': scan_result
            }
            
            save_to_csv(scan_data)
            
    cv2.imshow("QR Code Scanner", frame)
    if cv2.waitKey(1) == 27:  # Press 'Esc' to exit
        break

cap.release()
cv2.destroyAllWindows()
