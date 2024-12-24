# Import necessary libraries
from flask import Flask, request, jsonify
import nmap

# Initialize Flask app and Nmap scanner
app = Flask(__name__)
nm = nmap.PortScanner()

@app.route('/scan', methods=['POST'])
def scan_network():
    # Get target IP and ports from user input
    target = request.json.get('target')
    ports = request.json.get('ports', '1-1024')

    try:
        # Run Nmap scan
        nm.scan(hosts=target, ports=ports, arguments='-sV')
        scan_data = []

        for host in nm.all_hosts():
            host_data = {
                'host': host,
                'state': nm[host].state(),
                'ports': []
            }

            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_data = {
                        'port': port,
                        'service': nm[host][proto][port]['name'],
                        'state': nm[host][proto][port]['state']
                    }
                    host_data['ports'].append(port_data)

            scan_data.append(host_data)

        return jsonify(scan_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
