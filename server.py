from flask import Flask, request, jsonify, send_file #Used to simulate a simple webclient
from statistics import mean, stdev
from datetime import datetime, timedelta # Used to measure time
import pandas as pd # A data science module whICh was intended to be used to identify normal queries

app = Flask(__name__)

# Read data from a file (simulating database)
with open('data.txt') as f:
    DATA = f.read().splitlines()

# This is an intentionally vulnerable, static admin credential used for this model.
admin_credential = {"username": "admin", "password": "pwd123"}
# This is a dictionary used to track failed logon attempts.
failed_login_attempts = {}

# This is a simulated behaviour learning section.
# Ideally in an actual anomaly based system, the system would learn normal activity for IoT clients
normal_queries = [
    {"ip": "192.168.1.1", "query_length": 10},
    {"ip": "192.168.1.2", "query_length": 15},
    {"ip": "192.168.1.3", "query_length": 14},
]

# Create a data frame for normal queries
df_normal = pd.DataFrame(normal_queries)

# Creates a "normal" query length by identifying an average length of a query.
mean_len = df_normal['query_length'].mean()
stdev_len = df_normal['query_length'].std()


# This is the core Anomaly-based IPS code, which initialized the AnomalyBasedIPS class
# This labels multiple methods to block common IoT exploits.
class AnomalyBasedIPS:
    def __init__(self, mean, stdev, threshold=5):
        self.mean = mean
        self.stdev = stdev
        self.threshold = threshold
        self.blocked_ips = set()
        self.failed_attempts = {}

# Defines the function is_anomalous to label anomalous behaviour
    def is_anomalous(self, ip, query_length):
        z_score = (query_length - self.mean) / self.stdev
        if abs(z_score) > self.threshold:
            self.blocked_ips.add(ip)
            return True
        return False

# Function to track failed logons and to block any ip address with greater than 3 logon failures within 10 seconds.
    def track_failed_login(self, ip):
        now = datetime.now()
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        self.failed_attempts[ip].append(now)
        self.failed_attempts[ip] = [time for time in self.failed_attempts[ip] if now - time <= timedelta(seconds=10)]
        if len(self.failed_attempts[ip]) > 3:
            self.blocked_ips.add(ip)

# A function to remove blocked IP's from the blocked IP list

    def remove_blocked_ip(self, ip):
        self.blocked_ips.discard(ip)
        self.failed_attempts.pop(ip, None)

# A function to retrieve list of blocked IP's
    def get_blocked_ips(self):
        return list(self.blocked_ips)

#This function creates an instance to calculte mean and standard deviation.
ips = AnomalyBasedIPS(mean_len, stdev_len)


# This is the main directory for the model HTTP server that allows web access
@app.route('/')
def home():
    return """
    <!doctype html>
    <html lang="en">
    <head>
      <title> Home Surveillance Dashboard</title>
    </head>
    <body>
      <h1>Welcome to your Home Surveillance Dashboard!</h1>
      <ul>
        <li><a href="/query?q=info1">Query Data</a></li>
        <li><a href="/status">Check Intruder Status</a></li>
        <li><a href="/admin">Admin Panel</a></li>
      </ul>
    </body>
    </html>
    """

# This is to define the query directory which will be simulating the sensor reaching out to the server for data
@app.route('/query', methods=['GET'])
#This section is used to handle queries and check if the detected IP address is part of the anomaly block list
def query_data():
    query_param = request.args.get('q')
    client_ip = request.remote_addr

    # Calculate query length
    query_length = len(query_param)

    # IPS checks for anomalie
    if client_ip in ips.blocked_ips:
        return jsonify({"error": "Your IP is blocked due to detected anomalies."}), 403

    if ips.is_anomalous(client_ip, query_length):
        return jsonify({"error": "Anomalous activity detected!"}), 403

    # Normal search behavior
    if query_param in DATA:
        return jsonify({"result": query_param}), 200
    else:
        return jsonify({"error": "Data not found."}), 404


# This is an endpoint to model a server receiving data from a sensor
@app.route('/sensor', methods=['POST'])
def sensor_data():
    data = request.json
    client_ip = request.remote_addr

    # Simulate storing sensor data
    print(f"Received sensor data from {client_ip}: {data}")

    # Respond to the client
    return jsonify({"status": "success", "message": "Sensor data received."}), 200


# A model configuration directory to simulate receiving configuration data from sensors
@app.route('/config', methods=['POST'])
def configure_device():
    config_data = request.json
    client_ip = request.remote_addr

    # Simulating applying configurations
    print(f"Received configuration from {client_ip}: {config_data}")


    return jsonify({"status": "success", "message": "Configuration applied."}), 200


# This is to model an enpoint to check status, at this time it is just static
@app.route('/status', methods=['GET'])
def device_status():
    client_ip = request.remote_addr

    # Simulate returning device status
    status = {
        "device_id": "12345",
        "status": "online",
        "Person Detected?": "Yes",
        "ip": client_ip
    }

    return jsonify(status), 200


# These are to model intentionally vulnerable and sensitive directories.
@app.route('/admin', methods=['GET'])
def admin_panel():
    return """
    <!doctype html>
    <html lang="en">
    <head>
      <title>Admin Panel</title>
    </head>
    <body>
      <h1>Admin Panel Login</h1>
      <form action="/admin/login" method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
      </form>
    </body>
    </html>
    """

# This allows for vulnerable admin directory to allow for a logon session to test brute force attacks.
@app.route('/admin/login', methods=['POST'])
def admin_login():
    username = request.form['username']
    password = request.form['password']
    client_ip = request.remote_addr

# Blocks automatically if part of block list
    if client_ip in ips.blocked_ips:
        return "<h3>Access denied. Your IP has been blocked.</h3>"

# Checks entered values against the static admin password
    if username == admin_credential['username'] and password == admin_credential['password']:
        return "<h3>Login successful! Welcome to the admin panel!</h3>"
    else:
# On a failed logon attempt, it adds a counter to the failed logon list
        ips.track_failed_login(client_ip)
        return "<h3>Login failed! Invalid credentials.</h3>"

# The config directory.
@app.route('/config-file', methods=['GET'])
def config_file():
    if request.remote_addr in ips.blocked_ips:
        return "<h3>Access denied. Your IP has been blocked.</h3>"
    return send_file('config.txt')

# Directory to list blocked IP's for testing
@app.route('/ips/blocked', methods=['GET'])
def get_blocked_ips():
    return jsonify({"blocked_ips": ips.get_blocked_ips()}), 200

# It is noted that in an actual system a client should not be able to remove their own blocked IP but it is allowed for testing.
@app.route('/ips/unblock', methods=['POST'])
def unblock_ip():
    ip_to_unblock = request.json.get('ip')
    ips.remove_blocked_ip(ip_to_unblock)
    return jsonify({"status": "success", "message": f"IP {ip_to_unblock} unblocked."}), 200

#Initiates a web server socket on all IP addresses on port 8080.
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
