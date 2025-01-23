from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    api_key = data.get('api_key')
    url = data.get('url')

    # Define the API endpoints
    scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
    report_url = "https://www.virustotal.com/vtapi/v2/url/report"
    
    # Submit URL for scanning
    scan_params = {'apikey': api_key, 'url': url}
    scan_response = requests.post(scan_url, data=scan_params)
    scan_result = scan_response.json()
    
    if scan_response.status_code != 200:
        return jsonify({'error': scan_result.get('error', 'Unknown error')}), 400

    # Get scan report
    report_params = {'apikey': api_key, 'resource': scan_result['scan_id']}
    report_response = requests.get(report_url, params=report_params)
    report_result = report_response.json()
    
    if report_response.status_code != 200:
        return jsonify({'error': report_result.get('error', 'Unknown error')}), 400

    return jsonify(report_result)

if __name__ == '__main__':
    app.run(debug=True)
