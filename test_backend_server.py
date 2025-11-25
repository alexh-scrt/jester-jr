#!/usr/bin/env python3
"""
Multi-port backend server for comprehensive Jester Jr reverse proxy testing
Supports multiple ports with different behaviors for thorough testing
"""
import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import sys

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Thread-per-request HTTP server"""
    daemon_threads = True

class TestBackendHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Custom logging with port identification"""
        port = self.server.server_address[1]
        print(f"🟢 Backend[{port}]: {format % args}")
    
    def get_server_info(self):
        """Get server identification info"""
        port = self.server.server_address[1]
        server_type = {
            9090: "Primary Backend",
            9091: "Public API Backend", 
            9092: "Protected API Backend",
            9093: "V2 API Backend",
            9094: "Upload Backend",
            9095: "Admin Backend",
            9096: "Timeout Test Backend"
        }.get(port, f"Test Backend {port}")
        
        return {
            "port": port,
            "server_type": server_type,
            "timestamp": time.time()
        }
    
    def do_GET(self):
        """Handle GET requests with port-specific responses"""
        port = self.server.server_address[1]
        server_info = self.get_server_info()
        
        # Special behavior for timeout test backend
        if port == 9096:
            print(f"🕐 Timeout test backend - delaying response for 10 seconds...")
            time.sleep(10)
        
        # Different response types based on path and port
        if self.path.startswith('/health'):
            response_data = {
                "status": "healthy",
                "message": f"Health check OK from {server_info['server_type']}",
                "server": server_info,
                "path": self.path
            }
        elif self.path.startswith('/error'):
            # Test error responses
            self.send_error_response()
            return
        elif self.path.startswith('/large'):
            # Test large response (for size limit testing)
            self.send_large_response()
            return
        elif port == 9095:  # Admin backend
            response_data = {
                "admin_message": "Admin backend response",
                "path": self.path,
                "server": server_info,
                "admin_data": {
                    "users": ["admin", "manager"],
                    "permissions": ["read", "write", "delete"]
                }
            }
        elif port == 9093:  # V2 API backend
            response_data = {
                "api_version": "v2",
                "message": "V2 API response",
                "path": self.path,
                "server": server_info,
                "features": ["enhanced", "secure", "fast"]
            }
        else:
            # Standard response
            response_data = {
                "message": f"GET response from {server_info['server_type']}",
                "path": self.path,
                "method": "GET",
                "server": server_info,
                "headers_received": dict(self.headers)
            }
        
        self.send_json_response(200, response_data)
    
    def do_POST(self):
        """Handle POST requests"""
        port = self.server.server_address[1]
        server_info = self.get_server_info()
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
        
        # Parse JSON body if possible
        parsed_body = None
        try:
            if body:
                parsed_body = json.loads(body)
        except:
            parsed_body = {"raw_body": body}
        
        # Special handling for upload backend
        if port == 9094:
            response_data = {
                "upload_status": "received",
                "message": "File upload processed",
                "content_length": content_length,
                "server": server_info,
                "body_preview": body[:100] if len(body) > 100 else body
            }
        else:
            response_data = {
                "message": f"POST received by {server_info['server_type']}",
                "path": self.path,
                "method": "POST",
                "server": server_info,
                "body_received": parsed_body,
                "content_length": content_length,
                "headers_received": dict(self.headers)
            }
        
        self.send_json_response(200, response_data)
    
    def do_PUT(self):
        """Handle PUT requests"""
        server_info = self.get_server_info()
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
        
        response_data = {
            "message": f"PUT received by {server_info['server_type']}",
            "path": self.path,
            "method": "PUT",
            "server": server_info,
            "body_received": body
        }
        
        self.send_json_response(200, response_data)
    
    def do_PATCH(self):
        """Handle PATCH requests"""
        server_info = self.get_server_info()
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
        
        response_data = {
            "message": f"PATCH received by {server_info['server_type']}",
            "path": self.path,
            "method": "PATCH",
            "server": server_info,
            "body_received": body
        }
        
        self.send_json_response(200, response_data)
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        server_info = self.get_server_info()
        
        response_data = {
            "message": f"DELETE received by {server_info['server_type']}",
            "path": self.path,
            "method": "DELETE",
            "server": server_info,
            "warning": "Resource would be deleted"
        }
        
        self.send_json_response(200, response_data)
    
    def send_json_response(self, status_code, data):
        """Send JSON response with proper headers"""
        response_body = json.dumps(data, indent=2).encode()
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body)))
        self.send_header('X-Backend-Server', f"TestBackend-{self.get_server_info()['port']}")
        self.send_header('X-Server-Type', self.get_server_info()['server_type'])
        self.end_headers()
        
        self.wfile.write(response_body)
    
    def send_error_response(self):
        """Send various error responses for testing"""
        port = self.server.server_address[1]
        
        if '/error/404' in self.path:
            self.send_error(404, "Not Found")
        elif '/error/403' in self.path:
            self.send_error(403, "Forbidden")
        elif '/error/500' in self.path:
            self.send_error(500, "Internal Server Error")
        elif '/error/502' in self.path:
            self.send_error(502, "Bad Gateway")
        else:
            self.send_error(400, "Bad Request")
    
    def send_large_response(self):
        """Send large response for size limit testing"""
        # Create a response larger than 1MB (1048576 bytes)
        large_data = {
            "message": "Large response for size testing",
            "server": self.get_server_info(),
            "large_field": "x" * 2000000  # 2MB of data
        }
        
        self.send_json_response(200, large_data)

def start_backend_server(port, server_name):
    """Start a backend server on the specified port"""
    try:
        server = ThreadedHTTPServer(('127.0.0.1', port), TestBackendHandler)
        print(f"🟢 {server_name} running on http://127.0.0.1:{port}")
        server.serve_forever()
    except Exception as e:
        print(f"❌ Failed to start {server_name} on port {port}: {e}")

def main():
    # Backend server configurations
    backends = [
        (9090, "Primary Backend"),
        (9091, "Public API Backend"),
        (9092, "Protected API Backend"),
        (9093, "V2 API Backend"),
        (9094, "Upload Backend"),
        (9095, "Admin Backend"),
        # (9096, "Timeout Test Backend"),  # Uncomment to test timeout behavior
    ]
    
    print("=" * 70)
    print("🚀 Starting Jester Jr Test Backend Servers")
    print("=" * 70)
    
    # Start all backend servers in separate threads
    threads = []
    for port, name in backends:
        thread = threading.Thread(target=start_backend_server, args=(port, name), daemon=True)
        thread.start()
        threads.append(thread)
        time.sleep(0.5)  # Stagger startup
    
    print("\n🟢 All backend servers started successfully!")
    print("   Ready for Jester Jr reverse proxy testing")
    print("\n📋 Available endpoints for testing:")
    print("   /health - Health check endpoints")
    print("   /error/404, /error/403, /error/500 - Error responses")
    print("   /large - Large response (>1MB) for size limit testing")
    print("   Any other path - Standard responses with port identification")
    print("\n💡 Press Ctrl+C to stop all servers")
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping all backend servers...")
        return 0

if __name__ == '__main__':
    sys.exit(main())