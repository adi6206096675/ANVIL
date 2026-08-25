# engine/proxy/chaos.py
import time
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

class ChaosHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._apply_chaos()
        
    def do_POST(self):
        self._apply_chaos()

    def _apply_chaos(self):
        chaos_roll = random.randint(1, 100)
        
        # 20% chance to drop the connection entirely
        if chaos_roll <= 20:
            print(f"[CHAOS PROXY] Dropping packet for {self.path} (Simulating network failure)")
            self.close_connection = True
            return

        # 30% chance to inject severe latency (3 to 8 seconds)
        elif chaos_roll <= 50:
            latency = random.uniform(3.0, 8.0)
            print(f"[CHAOS PROXY] Injecting {latency:.2f}s latency into {self.path}")
            time.sleep(latency)
            self._send_success()

        # 50% chance to let it pass normally
        else:
            self._send_success()

    def _send_success(self):
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "chaos_passed"}')
        except Exception:
            pass

class AnvilChaosProxy:
    """Injects network faults, latency spikes, and packet drops."""
    def __init__(self, port: int = 8081):
        self.server_address = ("127.0.0.1", port)
        self.httpd = HTTPServer(self.server_address, ChaosHandler)

    def start(self):
        print(f"[ANVIL CHAOS] Network sabotage proxy active on http://127.0.0.1:{self.server_address[1]}")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()