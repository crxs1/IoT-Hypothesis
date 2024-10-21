import requests
import time

# This code is a script to simulate multiple IoT client actions, including those of a sensor and those of a web client

# This function is used to simulate normal queries to the query directory
def send_normal_request():
    response = requests.get('http://localhost:8080/query', params={'q': 'info1'})
    print('Normal request:', response.json())

# This function simulates an abnormal query to get the IPS to trigger a block
def send_anomalous_request():
    # Simulate an anomalously long query
    response = requests.get('http://localhost:8080/query', params={'q': 'a' * 100})
    print('Anomalous request:', response.json())

# Function to simulate sending sensor data to the server
def send_sensor_data():
    sensor_data = {
        "Detected User": 1,
        "App Detected":0 ,
        "Alarm Request Sent?": 1,
    }
    response = requests.post('http://localhost:8080/sensor', json=sensor_data)
    print('Sensor data:', response.json())

# Function to send configuration data to the server
def configure_device():
    config_data = {
        "sampling_rate": 5,
        "threshold": 75
    }
    response = requests.post('http://localhost:8080/config', json=config_data)
    print('Configure device:', response.json())

# Function to send a query to get the device status
def check_device_status():
    response = requests.get('http://localhost:8080/status')
    print('Device status:', response.json())

# is used to test reaching out to the admin panel
def access_admin_panel():
    response = requests.get('http://localhost:8080/admin')
    print('Admin panel:', response.text)

# Function to attempt a logon with supplied data
def attempt_login(username, password):
    response = requests.post('http://localhost:8080/admin/login', data={'username': username, 'password': password})
    print(f'Login attempt with {username}:{password}:', response.text)


def access_config_file():
    response = requests.get('http://localhost:8080/config-file')
    print('Config file:', response.text)


def view_blocked_ips():
    response = requests.get('http://localhost:8080/ips/blocked')
    print('Blocked IPs:', response.json())


def unblock_ip(ip):
    response = requests.post('http://localhost:8080/ips/unblock', json={"ip": ip})
    print(f'Unblocking IP {ip}:', response.json())


# The below are multiple tests that run and call previously established functions
print("Displaying Blocked IPs:")
view_blocked_ips()

print("\nSending normal request:")
send_normal_request()

time.sleep(1)

print("\nSending another normal request:")
send_normal_request()

time.sleep(1)

print("\nSending anomalous request:")
send_anomalous_request()

time.sleep(1)

print("\nSending another normal request after anomaly detection update:")
send_normal_request()

time.sleep(1)

# It is noted that expected activity is not blocked as to allow for availability.
# It is noted that this makes the system to potential exploits of service exploits.
print("\nSending sensor data:")
send_sensor_data()

time.sleep(1)

print("\nConfiguring device:")
configure_device()

time.sleep(1)

print("\nChecking device status:")
check_device_status()

time.sleep(1)

print("\nUnblocking IP:")
unblock_ip("127.0.0.1")

print("\nAccessing admin panel:")
access_admin_panel()

time.sleep(1)

#This sections attempts logon with the correct password while unblocked
print("\nAttempting correct login:")
attempt_login("admin", "pwd123")

time.sleep(1)

print("\nAttempting incorrect login multiple times:")
for _ in range(6):
    attempt_login("admin", "wrongpassword")
    time.sleep(1)

time.sleep(1)

print("\nDisplaying Blocked IPs after failed logins:")
view_blocked_ips()

time.sleep(1)

print("\nAttempting correct login after block:")
attempt_login("admin", "pwd123")


print("\nUnblocking IP for further testing:")
unblock_ip("127.0.0.1")

time.sleep(1)

print("\nDisplaying Blocked IPs after unblocking:")
view_blocked_ips()

time.sleep(1)

