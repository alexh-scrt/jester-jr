#!/usr/bin/env python3
"""
Simple backend server for testing Jester Jr reverse proxy
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import socket

class BackendHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Custom logging"""
        print(f"🟢 Backend: {format % args}")
    
    def _send_response(self, method, body=None):
        """Common response handling with error protection"""
        try:
            response_data = {
                "message": f"Hello from backend!",
                "path": self.path,
                "method": method,
                "headers": dict(self.headers)
            }
            
            if body:
                response_data["body_received"] = body
            
            response_body = json.dumps(response_data, indent=2).encode()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_body)))
            self.send_header('X-Backend-Server', 'Python-Test-Backend')
            self.end_headers()
            
            self.wfile.write(response_body)
            
        except (BrokenPipeError, ConnectionResetError, socket.error):
            # Client disconnected before we could send response
            # This is normal in HTTP proxying scenarios
            pass
        except Exception as e:
            print(f"🟡 Backend error: {e}")

    def do_GET(self):
        """Handle GET requests"""
        self._send_response("GET")
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
            self._send_response("POST", body)
        except Exception as e:
            print(f"🟡 POST error: {e}")

    def do_PUT(self):
        """Handle PUT requests"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
            self._send_response("PUT", body)
        except Exception as e:
            print(f"🟡 PUT error: {e}")

    def do_PATCH(self):
        """Handle PATCH requests"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
            self._send_response("PATCH", body)
        except Exception as e:
            print(f"🟡 PATCH error: {e}")

    def do_DELETE(self):
        """Handle DELETE requests"""
        self._send_response("DELETE")

    def do_HEAD(self):
        """Handle HEAD requests"""
        self._send_response("HEAD")
        
    def do_OPTIONS(self):
        """Handle OPTIONS requests"""
        self._send_response("OPTIONS")

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 9090), BackendHandler)
    print("🟢 Backend server running on http://127.0.0.1:9090")
    print("   (This is the server Jester Jr will proxy to)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🟢 Backend server stopped")