import asyncio
import json
import socket
import subprocess
import time

HOST = "127.0.0.1"
PORT = 5140

def fetch_recent_logs():
    # Fetch logs from the last 5 seconds to ensure we don't miss any between polling cycles.
    # Use SilentlyContinue to ignore permission errors on some logs.
    ps_command = """
    $start = (Get-Date).AddSeconds(-5)
    $events = Get-WinEvent -FilterHashtable @{LogName='Application','System'; StartTime=$start} -ErrorAction SilentlyContinue
    if ($events) {
        $events | Select-Object TimeCreated, Id, LevelDisplayName, Message, ProviderName, MachineName | ConvertTo-Json -Compress
    }
    """
    
    # Run the PowerShell command
    result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_command], capture_output=True, text=True)
    
    out = result.stdout.strip()
    if not out:
        return []
        
    try:
        # PowerShell might return a single JSON object or a list of JSON objects
        data = json.loads(out)
        if isinstance(data, dict):
            return [data]
        return data
    except Exception as e:
        print(f"Error parsing JSON: {e}")
        return []

async def live_stream():
    print(f"Starting Live Windows Event Stream to ULPF Pipeline on {HOST}:{PORT}...")
    print("Keep this running while you use your PC to see real-time logs appear on the Dashboard!")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seen_events = set()
    
    while True:
        events = fetch_recent_logs()
        sent_count = 0
        
        # Windows events are usually newest first, we reverse to send chronological
        for evt in reversed(events):
            # Create a unique ID for deduplication since we query overlapping 5-second windows
            time_created = evt.get("TimeCreated", "")
            
            # PowerShell JSON serialization handles dates strangely sometimes, but we just need a unique string
            evt_id = f"{time_created}-{evt.get('Id', '')}-{str(evt.get('Message', ''))[:50]}"
            
            if evt_id not in seen_events:
                seen_events.add(evt_id)
                
                # Transform to a structure our windows_event.yaml regex will easily catch
                payload = {
                    "MachineName": evt.get("MachineName", "UNKNOWN"),
                    "EventID": evt.get("Id", 0),
                    "Message": evt.get("Message", ""),
                    "Source": evt.get("ProviderName", ""),
                    "Level": evt.get("LevelDisplayName", ""),
                }
                
                payload_bytes = json.dumps(payload).encode("utf-8")
                
                try:
                    sock.sendto(payload_bytes, (HOST, PORT))
                    sent_count += 1
                except Exception as e:
                    print(f"Failed to send packet: {e}")
                
        if sent_count > 0:
            print(f"[{time.strftime('%H:%M:%S')}] Forwarded {sent_count} live event(s) to pipeline.")
                
        # Keep the deduplication set from growing infinitely
        if len(seen_events) > 2000:
            seen_events.clear()
            
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    asyncio.run(live_stream())
