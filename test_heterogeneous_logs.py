import socket
import time
import json

HOST = "127.0.0.1"
PORT = 5140

# A collection of raw, real-world log formats from various platforms
heterogeneous_logs = [
    # 1. Linux SSHD (auth.log) - Standard Syslog
    "Sep 10 23:14:02 ubuntu-server sshd[14534]: Failed password for root from 192.168.1.50 port 54321 ssh2",
    "Sep 10 23:14:05 ubuntu-server sshd[14534]: Accepted publickey for admin from 10.0.0.5 port 55555 ssh2: RSA SHA256:abcd1234efgh5678",
    
    # 2. Apple iOS / macOS (Unified Logging / Alf)
    "Sep 10 23:15:11 MacBook-Pro kernel[0]: ALF, IPFW: Stealth Mode connection attempt to UDP 192.168.1.100:5353 from 192.168.1.1:53",
    '{"timestamp":"2026-09-10 23:16:00.123","processID":456,"threadID":789,"subsystem":"com.apple.security","category":"auth","message":"User authentication failed for touchID"}',
    
    # 3. Cisco ASA Firewall
    "%ASA-4-106023: Deny udp src outside:192.168.2.5/53 dst inside:10.0.0.2/5353 by access-group \"outside_in\"",
    "%ASA-6-302013: Built inbound TCP connection 123456 for outside:192.168.2.10/443 (192.168.2.10/443) to inside:10.0.0.5/54321 (10.0.0.5/54321)",
    
    # 4. AWS CloudTrail (JSON)
    json.dumps({
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
        "eventTime": "2026-09-10T23:18:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "DeleteBucket",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.0.0",
        "requestParameters": {"bucketName": "critical-prod-data"}
    }),
    
    # 5. Palo Alto Networks (CSV format syslog)
    "1,2026/09/10 23:20:00,00123456789,THREAT,vulnerability,1,2026/09/10 23:19:59,10.0.0.2,192.168.1.100,0.0.0.0,0.0.0.0,Rule1,admin,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,syslog,2026/09/10 23:20:00,12345,1,80,8080,0,0,0x400000,tcp,alert,\"\",Attempted Admin Privilege Gain(30001),any,informational,client-to-server,0,0x0,192.168.0.0-192.168.255.255,10.0.0.0-10.255.255.255,0,,0,,,0,,,,,,,,0,0,0,0,0",
]

def send_logs():
    print(f"Sending {len(heterogeneous_logs)} completely different log formats to ULPF UDP Listener on {HOST}:{PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for log in heterogeneous_logs:
        # Convert string to bytes and send via UDP
        payload = log.encode('utf-8')
        sock.sendto(payload, (HOST, PORT))
        print(f"-> Sent log ({len(payload)} bytes)")
        time.sleep(0.5) # Slight delay to let us watch the dashboard update organically
        
    print("Done! Check the ULPF Dashboard or the output JSONL sink.")
    sock.close()

if __name__ == "__main__":
    send_logs()
