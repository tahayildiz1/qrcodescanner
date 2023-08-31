import cv2
import requests

API_KEY = "API-KEY"

def check_link_with_virustotal(url):
    params = {'apikey': API_KEY, 'resource': url}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    result = response.json()
    return result

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

    cv2.imshow("QR Code Scanner", frame)
    if cv2.waitKey(1) == 27:  # Press 'Esc' to exit
        break

cap.release()
cv2.destroyAllWindows()
