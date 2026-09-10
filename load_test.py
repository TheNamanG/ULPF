import asyncio
import json
import socket
from pathlib import Path

async def load_test(host: str = "127.0.0.1", port: int = 5140) -> None:
    logs_file = Path("windows_logs_5000.json")
    if not logs_file.exists():
        print("Error: windows_logs_5000.json not found.")
        return
        
    print(f"Loading logs from {logs_file}...")
    with open(logs_file, "r", encoding="utf-16") as f:
        # PowerShell ConvertTo-Json might output a top-level list
        data = json.load(f)
        
    if not isinstance(data, list):
        print("Expected a JSON array of events.")
        return
        
    # Multiply by 2 to reach 10,000 logs
    data = data * 2
        
    print(f"Loaded {len(data)} events. Blasting to {host}:{port} via UDP...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # We will send batches to not immediately blow up the OS socket buffer
    success = 0
    for evt in data:
        payload = json.dumps(evt).encode("utf-8")
        try:
            sock.sendto(payload, (host, port))
            success += 1
        except Exception as e:
            print(f"Error sending packet: {e}")
            break
            
        # tiny sleep to yield loop context and prevent buffer overrun
        await asyncio.sleep(0.0001)
        
    print(f"Successfully sent {success} UDP packets.")
    sock.close()

if __name__ == "__main__":
    asyncio.run(load_test())
