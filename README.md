# QR Code Scanner and VirusTotal Link Checker

This is a Python script that uses the computer's camera to scan QR codes, extract URLs from them, and then checks the extracted URLs for safety using the VirusTotal API.

## Installation

1. Clone this repository:

2. Install the required libraries using pip:

3. Replace `YOUR_VIRUSTOTAL_API_KEY` in the script with your actual VirusTotal API key.

## Usage

Run the script using the following command:

The script will activate your camera, and you can use it to scan QR codes. It will then display information about the scanned QR code and perform a VirusTotal scan on the extracted URL.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- This script uses the `opencv-python` library for camera usage and QR code scanning.
- It also uses the `requests` library to interact with the VirusTotal API.

## Disclaimer

This script is provided as-is and may not be suitable for all use cases. Use at your own risk.

