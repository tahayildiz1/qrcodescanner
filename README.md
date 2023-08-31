# QR Code Scanner with VirusTotal Integration

This is a Python script that uses your webcam to scan QR codes and then performs various checks on the decoded URLs. It utilizes the VirusTotal API to check the safety of the scanned URLs and the IPinfo API to gather information about the public IP address.

## Prerequisites

Before you can run the script, you need to have the following:

- Python 3.x installed
- OpenCV (`cv2`) library installed
- Requests library installed
- An API key from VirusTotal
- An API key from IPinfo

## Installation

1. Clone this repository to your local machine.
2. Install the required Python libraries using the following command:
3. Replace the placeholders `'VirusTotal-API-KEY'` and `'IPinfo-API-KEY'` in the code with your actual VirusTotal and IPinfo API keys.

## Usage

1. Run the script by executing the following command:
2. The script will open your webcam and start scanning for QR codes. When a QR code is detected, the decoded information will be displayed in the terminal.
3. The script will then check the safety of the decoded URL using the VirusTotal API and display the results.
4. It will also retrieve your public IP address using `ifconfig.io` and gather additional information using the IPinfo API, such as location, organization, and hostname.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- This script uses the VirusTotal API and IPinfo API to enhance QR code scanning functionality.
- The OpenCV library is used for QR code detection and webcam integration.

