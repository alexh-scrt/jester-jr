# 📖 Jester Jr - Complete Usage Guide

Comprehensive guide to configuring and using Jester Jr reverse proxy.

## 📑 Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Configuration Reference](#configuration-reference)
4. [Rule Examples](#rule-examples)
5. [Rule Evaluation](#rule-evaluation)
6. [Advanced Usage](#advanced-usage)
7. [Testing](#testing)
8. [Logging](#logging)
9. [Troubleshooting](#troubleshooting)
10. [Performance Tips](#performance-tips)
11. [Production Deployment](#production-deployment)
12. [Security Best Practices](#security-best-practices)

---

## Installation

### From Source

```bash
# Prerequisites: Rust 1.75+
rustc --version

# Clone repository
git clone https://github.com/yourusername/jester-jr
cd jester-jr

# Build release version (optimized)
cargo build --release

# Binary location
ls -lh target/release/jester-jr

# Make it executable (if needed)
chmod +x target/release/jester-jr

# Optional: Install system-wide
sudo cp target/release/jester-jr /usr/local/bin/
```

### Pre-built Binaries

Coming soon! Check releases page.

---

## Quick Start

### 1. Create Configuration

**Minimal config** (`jester-jr.toml`):
```toml
[proxy]
listen_address = "127.0.0.1:8080"
backend_address = "127.0.0.1:9090"
timeout_seconds = 30
```

### 2. Start Backend

For testing, start a simple backend:

```bash
# Python HTTP server
python3 -m http.server 9090

# Or Node.js
npx http-server -p 9090

# Or any web application on port 9090
```

### 3. Run Jester Jr

```bash
# Use default config (./jester-jr.toml)
./target/release/jester-jr

# Or specify config path
./target/release/jester-jr /path/to/config.toml

# Or with explicit path
./target/release/jester-jr ./jester-jr.toml
```

### 4. Test It

```bash
# Simple GET request
curl http://localhost:8080/

# With headers
curl -H "Authorization: Bearer token" http://localhost:8080/api/test

# POST request
curl -X POST -d '{"test":"data"}' http://localhost:8080/api/create

# Verbose output
curl -v http://localhost:8080/
```

---

## Configuration Reference

### Proxy Settings

```toml
[proxy]
# Address:port to listen on (required)
listen_address = "127.0.0.1:8080"

# Backend server address:port (required)
backend_address = "127.0.0.1:9090"

# Connection timeout in seconds (required)
timeout_seconds = 30
```

### Request Rules

```toml
[[request_rules]]
# Human-readable rule name (required)
name = "Rule description"

# Action: "allow" or "deny" (required)
action = "allow"

# Optional: Regex pattern for path matching
path_regex = "^/api/.*"

# Optional: Array of allowed/denied HTTP methods
methods = ["GET", "POST", "PUT"]

# Optional: Required header name (case-insensitive)
require_header = "Authorization"
```

**All fields:**
- `name` (string, required): Descriptive name for logging
- `action` (string, required): `"allow"` or `"deny"`
- `path_regex` (string, optional): Regex pattern for URL path
- `methods` (array, optional): HTTP methods to match
- `require_header` (string, optional): Header that must be present

### Response Rules

```toml
[[response_rules]]
# Human-readable rule name (required)
name = "Rule description"

# Action: "allow" or "deny" (required)
action = "deny"

# Optional: Array of status codes to match
status_codes = [500, 502, 503]

# Optional: Maximum response size in bytes
max_size_bytes = 10485760  # 10 MB
```

**All fields:**
- `name` (string, required): Descriptive name for logging
- `action` (string, required): `"allow"` or `"deny"`
- `status_codes` (array, optional): HTTP status codes to match
- `max_size_bytes` (integer, optional): Max response body size

---

## Rule Examples

### Common Use Cases

#### 1. Block Admin Access

```toml
[[request_rules]]
name = "Block admin panel"
action = "deny"
path_regex = "^/admin/.*"
```

**Matches:**
- `/admin/users`
- `/admin/settings`
- `/admin/dashboard`

**Doesn't match:**
- `/api/admin` (doesn't start with /admin/)
- `/user/admin/profile`

#### 2. API with Authentication

```toml
# Allow authenticated API requests
[[request_rules]]
name = "API with auth"
action = "allow"
path_regex = "^/api/.*"
require_header = "Authorization"

# Deny API requests without auth
[[request_rules]]
name = "API without auth"
action = "deny"
path_regex = "^/api/.*"
```

**Order matters!** First rule checks for auth header, second catches remaining.

#### 3. Read-Only API

```toml
# Allow safe methods
[[request_rules]]
name = "Allow read operations"
action = "allow"
path_regex = "^/api/.*"
methods = ["GET", "HEAD", "OPTIONS"]

# Deny all other methods
[[request_rules]]
name = "Deny write operations"
action = "deny"
path_regex = "^/api/.*"
```

#### 4. Block Sensitive Paths

```toml
[[request_rules]]
name = "Block .git directory"
action = "deny"
path_regex = "^/\\.git/.*"

[[request_rules]]
name = "Block environment files"
action = "deny"
path_regex = "^/\\.env.*"

[[request_rules]]
name = "Block backup files"
action = "deny"
path_regex = ".*\\.(bak|backup|old|tmp)$"
```

#### 5. Hide Backend Errors

```toml
[[response_rules]]
name = "Hide server errors"
action = "deny"
status_codes = [500, 501, 502, 503, 504]
```

**Effect:** Clients get `502 Bad Gateway` instead of actual error

#### 6. Limit Response Size

```toml
[[response_rules]]
name = "Block large downloads"
action = "deny"
max_size_bytes = 52428800  # 50 MB
```

**Use case:** Prevent bandwidth exhaustion or DoS

#### 7. Method Blacklist

```toml
[[request_rules]]
name = "Block dangerous methods"
action = "deny"
methods = ["TRACE", "TRACK", "CONNECT"]
```

#### 8. Multi-path Protection

```toml
# Protect multiple paths with one rule
[[request_rules]]
name = "Protect sensitive areas"
action = "deny"
path_regex = "^/(admin|internal|private|secret)/.*"
```

---

## Rule Evaluation

### How Rules Work

1. **Order Matters**: Rules are evaluated **top to bottom**
2. **First Match Wins**: First rule that matches determines the action
3. **Default Behavior**: If no rules match, request/response is **allowed**

### Evaluation Logic

```
┌─────────────────────┐
│  Request Arrives    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Parse Headers      │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐
    │ For each     │
    │ request rule │◄─────┐
    └──────┬───────┘      │
           │              │
           ▼              │
    ┌──────────────┐     │
    │ Does rule    │     │
    │ apply?       │     │
    └──┬───────┬───┘     │
       │       │         │
      YES      NO        │
       │       └─────────┘
       ▼             Next rule
    ┌──────────────┐
    │ Apply action │
    │ (allow/deny) │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │   DONE       │
    └──────────────┘
```

### Matching Conditions

A rule applies when **ALL** of its conditions match:

```toml
[[request_rules]]
name = "Complex rule"
action = "allow"
path_regex = "^/api/.*"       # AND
methods = ["GET", "POST"]      # AND
require_header = "X-API-Key"   # must all match
```

**This rule only matches when:**
1. Path starts with `/api/`
2. AND method is GET or POST
3. AND `X-API-Key` header exists

### Special Case: require_header

The `require_header` field behaves specially:

**For ALLOW rules:**
```toml
action = "allow"
require_header = "Authorization"
```
- Header present → Apply allow action
- Header missing → Continue to next rule

**For DENY rules:**
```toml
action = "deny"
require_header = "Authorization"
```
- Header missing → Deny (with reason)
- Header present → Continue to next rule

---

## Advanced Usage

### Multiple Path Patterns

Create separate rules for different paths:

```toml
[[request_rules]]
name = "Public API"
action = "allow"
path_regex = "^/api/public/.*"

[[request_rules]]
name = "Private API with auth"
action = "allow"
path_regex = "^/api/private/.*"
require_header = "Authorization"

[[request_rules]]
name = "Private API without auth"
action = "deny"
path_regex = "^/api/private/.*"
```

### Cascading Rules

Use rule order to create complex logic:

```toml
# 1. First allow specific exceptions
[[request_rules]]
name = "Allow health check"
action = "allow"
path_regex = "^/health$"

# 2. Then apply broad restrictions
[[request_rules]]
name = "Block all admin"
action = "deny"
path_regex = "^/admin/.*"

# 3. Finally allow remaining
# (implicit: default is allow)
```

### Environment-Specific Configs

**Development** (`dev.toml`):
```toml
[proxy]
listen_address = "127.0.0.1:8080"
backend_address = "127.0.0.1:3000"
timeout_seconds = 60  # Longer for debugging

# Minimal filtering
[[request_rules]]
name = "Block admin"
action = "deny"
path_regex = "^/admin/.*"
```

**Production** (`prod.toml`):
```toml
[proxy]
listen_address = "0.0.0.0:8080"
backend_address = "10.0.1.100:8080"
timeout_seconds = 30

# Strict filtering
[[request_rules]]
name = "Whitelist only"
action = "allow"
path_regex = "^/api/.*"
methods = ["GET", "POST"]

[[request_rules]]
name = "Deny all else"
action = "deny"
path_regex = ".*"
```

---

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test module
cargo test config::tests

# Run specific test
cargo test test_parse_config
```

### Integration Testing

Test your configuration:

```bash
# Start backend
python3 -m http.server 9090 &
BACKEND_PID=$!

# Start proxy
./target/release/jester-jr test-config.toml &
PROXY_PID=$!
sleep 1

# Test allowed path
curl -w "%{http_code}\n" http://localhost:8080/api/test
# Expected: 200

# Test blocked path
curl -w "%{http_code}\n" http://localhost:8080/admin/test
# Expected: 403

# Cleanup
kill $PROXY_PID $BACKEND_PID
```

### Load Testing

Use `ab` (Apache Bench):

```bash
# 10000 requests, 100 concurrent
ab -n 10000 -c 100 http://localhost:8080/

# With keep-alive
ab -n 10000 -c 100 -k http://localhost:8080/
```

Use `wrk`:

```bash
# 30 seconds, 10 threads, 100 connections
wrk -t10 -c100 -d30s http://localhost:8080/
```

---

## Logging

### Log Format

```
✨ New connection from: 127.0.0.1:54321
📨 GET /api/users HTTP/1.1 from 127.0.0.1:54321
   Headers: 3 header(s)
✅ Request allowed
🔗 Connecting to backend at 127.0.0.1:9090
➡️  Forwarding request headers (86 bytes)
⬅️  HTTP/1.0 200 OK
   Headers: 5 header(s)
   Content-Length: 150 bytes
✅ Response allowed
⬅️  Forwarding response headers (183 bytes)
⬅️  Streaming response body...
   ⬅️  Response body complete: 150 bytes
✅ Proxy complete for 127.0.0.1:54321
```

### Log Indicators

- `✨` New connection
- `📨` Request received
- `✅` Allowed (request/response)
- `🚫` Blocked (request/response)
- `🔗` Backend connection
- `➡️` Outbound (to backend)
- `⬅️` Inbound (from backend)
- `⚠️` Warning
- `❌` Error

### Redirecting Logs

```bash
# To file
./jester-jr 2>&1 | tee jester-jr.log

# To syslog (with logger)
./jester-jr 2>&1 | logger -t jester-jr

# Structured (timestamp)
./jester-jr 2>&1 | ts '[%Y-%m-%d %H:%M:%S]' | tee jester-jr.log
```

---

## Troubleshooting

### Config file not found

**Error:**
```
❌ Failed to load config: No such file or directory
```

**Solutions:**
1. Check file path: `ls -l jester-jr.toml`
2. Use absolute path: `./jester-jr /full/path/to/config.toml`
3. Check current directory: `pwd`

### Regex compilation error

**Error:**
```
❌ Failed to compile request rules: regex parse error
    ^/api[invalid
          ^^^^^^^
```

**Solutions:**
1. Test regex online: https://regex101.com/
2. Escape special chars: `\.`, `\[`, `\]`, `\(`, `\)`
3. Use raw strings in TOML: `path_regex = "^/api/.*"`

### Backend connection refused

**Error:**
```
❌ Failed to connect to backend: Connection refused
```

**Solutions:**
1. Check backend is running: `curl http://127.0.0.1:9090/`
2. Check address/port in config
3. Check firewall rules
4. Verify network connectivity

### Port already in use

**Error:**
```
❌ Server error: Address already in use (os error 98)
```

**Solutions:**
1. Find process: `lsof -i :8080`
2. Kill process: `kill -9 <PID>`
3. Change port in config
4. Wait for TIME_WAIT to clear

### Requests timing out

**Symptoms:** Long delays, eventual timeout

**Solutions:**
1. Increase `timeout_seconds` in config
2. Check backend performance
3. Check network latency: `ping backend-host`
4. Reduce concurrent connections

### Rules not matching

**Symptom:** Expected block/allow not happening

**Solutions:**
1. Check rule order (first match wins)
2. Test regex: Use regex101.com
3. Check HTTP method (case-sensitive)
4. Enable verbose logging
5. Test with `--test` mode (coming soon)

---

## Performance Tips

### 1. Optimize Rule Order

Place most frequent matches first:

```toml
# Good: Common paths first
[[request_rules]]
name = "Allow API (90% of traffic)"
action = "allow"
path_regex = "^/api/.*"

[[request_rules]]
name = "Block admin (rare)"
action = "deny"
path_regex = "^/admin/.*"
```

### 2. Use Specific Regex

```toml
# Slow: backtracking
path_regex = ".*users.*"

# Fast: anchored
path_regex = "^/api/users(/.*)?$"
```

### 3. Minimize Rules

- Combine rules where possible
- Remove redundant rules
- Use catch-all at end

### 4. Backend Performance

Jester Jr is only as fast as your backend:
- Optimize backend response time
- Use HTTP keep-alive
- Enable backend caching

### 5. System Tuning

```bash
# Increase file descriptor limit
ulimit -n 65536

# Kernel parameters (Linux)
sudo sysctl -w net.core.somaxconn=4096
sudo sysctl -w net.ipv4.tcp_fin_timeout=30
```

---

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/jester-jr.service`:

```ini
[Unit]
Description=Jester Jr Reverse Proxy
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=proxy
Group=proxy
WorkingDirectory=/opt/jester-jr
ExecStart=/opt/jester-jr/jester-jr /opt/jester-jr/production.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/jester-jr

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

**Usage:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable jester-jr
sudo systemctl start jester-jr
sudo systemctl status jester-jr
```

### Docker Deployment

**Dockerfile** (multi-stage):
```dockerfile
# Build stage
FROM rust:1.75-alpine AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM alpine:latest
RUN apk add --no-cache libgcc
COPY --from=builder /app/target/release/jester-jr /usr/local/bin/
COPY jester-jr.toml /etc/jester-jr/
EXPOSE 8080
CMD ["jester-jr", "/etc/jester-jr/jester-jr.toml"]
```

**Build and run:**
```bash
docker build -t jester-jr .
docker run -p 8080:8080 -v ./config.toml:/etc/jester-jr/jester-jr.toml jester-jr
```

### Monitoring

```bash
# Watch logs
journalctl -u jester-jr -f

# Check metrics (coming soon)
curl http://localhost:8080/metrics

# Health check
curl -f http://localhost:8080/health || systemctl restart jester-jr
```

---

## Security Best Practices

### 1. Run as Non-Root

```bash
# Create dedicated user
sudo useradd -r -s /bin/false proxy

# Set ownership
sudo chown -R proxy:proxy /opt/jester-jr

# Run as user
sudo -u proxy ./jester-jr config.toml
```

### 2. Use TLS Termination

Put nginx/HAProxy in front:

```nginx
upstream jester {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://jester;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 3. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 8080/tcp
sudo ufw enable
```

### 4. Rate Limiting

Coming in v0.2.0! For now, use nginx:

```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

location /api {
    limit_req zone=api burst=20;
    proxy_pass http://jester;
}
```

### 5. Regular Updates

```bash
# Update Jester Jr
cd /opt/jester-jr
git pull
cargo build --release
sudo systemctl restart jester-jr

# Check version
./jester-jr --version
```

### 6. Audit Config

```bash
# Check for sensitive data
grep -i "password\|secret\|key" jester-jr.toml

# Validate permissions
ls -l jester-jr.toml
# Should be 600 or 640
```

---

## Next Steps

- Read [README.md](README.md) for project overview
- Check [ROADMAP.md](ROADMAP.md) for upcoming features
- Review [CONFIG_FILTERING_COMPLETE.md](CONFIG_FILTERING_COMPLETE.md) for internals
- Explore [LEARNING_SUMMARY.md](LEARNING_SUMMARY.md) for Rust concepts

---

**Questions?** Open an issue on GitHub or check the FAQ (coming soon).

**Last Updated:** November 2025