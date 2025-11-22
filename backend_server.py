#!/usr/bin/env python3
"""
Simple backend server for testing Jester Jr reverse proxy
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class BackendHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Custom logging"""
        print(f"🟢 Backend: {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        response_data = {
            "message": "Hello from backend!",
            "path": self.path,
            "method": "GET"
        }
        
        response_body = json.dumps(response_data, indent=2).encode()
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body)))
        self.send_header('X-Backend-Server', 'Python-Test-Backend')
        self.end_headers()
        
        self.wfile.write(response_body)
    
    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
        
        response_data = {
            "message": "POST received by backend",
            "path": self.path,
            "method": "POST",
            "body_received": body
        }
        
        response_body = json.dumps(response_data, indent=2).encode()
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body)))
        self.send_header('X-Backend-Server', 'Python-Test-Backend')
        self.end_headers()
        
        self.wfile.write(response_body)

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 9090), BackendHandler)
    print("🟢 Backend server running on http://127.0.0.1:9090")
    print("   (This is the server Jester Jr will proxy to)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🟢 Backend server stopped")