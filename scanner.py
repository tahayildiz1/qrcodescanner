import cv2
import requests
import json
import subprocess

API_KEY = "VirusTotal-API-KEY"
IPINFO_API_KEY = "IPinfo-API-KEY"  # Replace with your IPinfo API key

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
    region = ipinfo_data.get('region')
    city = ipinfo_data.get('city')
    org = ipinfo_data.get('org')
    hostname = ipinfo_data.get('hostname')
    
    print(f"Location (Country): {country}")
    print(f"Location (Region): {region}")
    print(f"Location (City): {city}")
    print(f"Organization: {org}")
    print(f"Hostname: {hostname}")
    
    # You can extract more fields as needed
    
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
        result = check_link_with_virustotal(decoded_info)

        # Get public IP address
        ip_address = get_public_ip()

        if ip_address:
            print("Public IP Address:", ip_address)
            get_ip_location(ip_address)  # Call the function to get IPinfo data
            
            if isinstance(result, dict):
                if result.get('response_code', -1) == 1:
                    scan_count = result.get('total', 0)
                    if result.get('positives', 0) == 0:
                        print(f"Gescannte Antiviren-Scanner: {scan_count}")
                        print("Link ist sicher.")
                    else:
                        print("Link ist möglicherweise unsicher.")
                        print(f"Gescannte Antiviren-Scanner: {scan_count}")
                        print("Erkannte Bedrohungen:")
                        for scan, info in result.get('scans', {}).items():
                            if info.get('detected'):
                                print(f"{scan}: {info.get('result', 'Keine Informationen')}")
                else:
                    print("Der Link konnte nicht überprüft werden.")
            else:
                print("Fehler bei der API-Antwort.")
        else:
            print("Konnte keine öffentliche IP-Adresse abrufen.")

    cv2.imshow("QR Code Scanner", frame)
    if cv2.waitKey(1) == 27:  # Press 'Esc' to exit
        break

cap.release()
cv2.destroyAllWindows()
