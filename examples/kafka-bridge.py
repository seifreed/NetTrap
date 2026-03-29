#!/usr/bin/env python3
"""TCP-to-Kafka bridge: receives JSON lines on TCP 5044, produces to Redpanda via HTTP Proxy."""
import socket, threading, urllib.request, json

PANDAPROXY = "http://redpanda:8082/topics/nettrap-events"

def handle(conn, addr):
    print(f"Connection from {addr}", flush=True)
    buf = b""
    while True:
        try:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Process complete lines
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.decode(errors="ignore").strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    payload = json.dumps({"records": [{"value": parsed}]}).encode()
                    req = urllib.request.Request(
                        PANDAPROXY,
                        data=payload,
                        headers={"Content-Type": "application/vnd.kafka.json.v2+json"},
                    )
                    urllib.request.urlopen(req, timeout=5)
                    proto = parsed.get("protocol", "?")
                    print(f"Produced [{proto}] from {parsed.get('src_ip','?')}", flush=True)
                except json.JSONDecodeError:
                    print(f"Invalid JSON: {line[:80]}", flush=True)
                except Exception as e:
                    print(f"Produce error: {e}", flush=True)
        except ConnectionResetError:
            break
    conn.close()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 5044))
srv.listen(10)
print("Bridge: TCP 5044 -> Kafka via Pandaproxy (streaming mode)", flush=True)
while True:
    conn, addr = srv.accept()
    threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
