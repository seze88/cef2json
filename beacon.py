import datetime
import random

# Configuration
source_ip = "192.168.1.10"
destination_ip = "8.8.8.8"
destination_port = 443
initial_time = datetime.datetime.now() - datetime.timedelta(days=1)  # Start 1 day ago
time_delta_seconds = 30  # Time delta between events (must be > 25 to meet threshold)
total_events = 31  # Total number of events (must be > 30)

# Function to generate traffic logs
def generate_logs():
    logs = []
    current_time = initial_time
    
    for i in range(total_events):
        log = {
            "TimeGenerated": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "DeviceName": "Firewall-1",
            "SourceUserID": f"user_{random.randint(1, 100)}",
            "SourceIP": source_ip,
            "SourcePort": random.randint(1024, 65535),
            "DestinationIP": destination_ip,
            "DestinationPort": destination_port,
            "ReceivedBytes": random.randint(500, 10000),
            "SentBytes": random.randint(500, 10000),
        }
        logs.append(log)
        current_time += datetime.timedelta(seconds=time_delta_seconds)  # Increment time by 30 seconds
    
    return logs

# Generate and print the logs
logs = generate_logs()
for log in logs:
    print(log)
