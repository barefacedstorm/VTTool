import requests

def scan_url(api_key, url):
    # Define the API endpoint for URL scanning
    scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
    report_url = "https://www.virustotal.com/vtapi/v2/url/report"
    
    # Step 1: Submit the URL for scanning
    scan_params = {'apikey': api_key, 'url': url}
    scan_response = requests.post(scan_url, data=scan_params)
    scan_result = scan_response.json()
    
    if scan_response.status_code != 200:
        print(f"Error: {scan_result.get('error', 'Unknown error')}")
        return
    
    # Step 2: Get the scan report
    report_params = {'apikey': api_key, 'resource': scan_result['scan_id']}
    report_response = requests.get(report_url, params=report_params)
    report_result = report_response.json()
    
    if report_response.status_code != 200:
        print(f"Error: {report_result.get('error', 'Unknown error')}")
        return
    
    # Step 3: Print the scan report
    print("URL Scan Report:")
    print(f"URL: {url}")
    print(f"Scan Date: {report_result['scan_date']}")
    print(f"Positives: {report_result['positives']}")
    print(f"Total: {report_result['total']}")
    print("Scan Results:")
    for scanner, result in report_result['scans'].items():
        print(f"{scanner}: {result['result']}")

# Main function to input URL and API key
def main():
    api_key = input("Enter your VirusTotal API key: ")
    url = input("Enter the URL you wish to scan: ")
    scan_url(api_key, url)

if __name__ == "__main__":
    main()
