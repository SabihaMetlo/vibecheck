from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys
import os

# Add api folder to path to import our handler
sys.path.append(os.path.join(os.path.dirname(__file__), 'api'))
from scan import handler as ScanHandler

class LocalHandler(ScanHandler, SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/scan':
            # Delegate to our serverless function handler
            ScanHandler.do_POST(self)
        else:
            self.send_error(404, "Not Found")
            
    def do_GET(self):
        if self.path.startswith('/api/'):
            self.send_error(404, "Not Found")
        else:
            super().do_GET()

if __name__ == '__main__':
    port = 8000
    server_address = ('', port)
    httpd = HTTPServer(server_address, LocalHandler)
    print(f"Serving on http://localhost:{port}...")
    httpd.serve_forever()
