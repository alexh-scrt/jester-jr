# 🎯 Jester Jr Multi-Listener Configuration Design

## Your Selected Design

✅ **Named Listeners** - Easy to reference and debug
✅ **Prefix OR Regex** - Maximum flexibility
✅ **Configurable Default** - Can reject or forward to default backend
✅ **Merged Rules** - Listener-level + Route-level rules
✅ **Path Rewriting** - Strip prefix when forwarding

---

## 📋 Complete Configuration Schema

### Basic Structure

```toml
# Global settings (optional)
[global]
log_level = "info"  # debug, info, warn, error
timeout_seconds = 30

# Named listeners
[listener."name"]
ip = "0.0.0.0"
port = 8080
description = "Optional description"
default_backend = "127.0.0.1:9090"  # Optional: fallback for unmatched routes
default_action = "reject"  # Optional: "reject" (404) or "forward" (use default_backend)

# TLS configuration (optional per listener)
[listener."name".tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"

# Listener-level rules (apply to ALL routes on this listener)
[[listener."name".request_rules]]
name = "Rule name"
action = "allow" | "deny"
# ... rule conditions ...

[[listener."name".response_rules]]
name = "Rule name"
action = "allow" | "deny"
# ... rule conditions ...

# Routes for this listener
[[listener."name".routes]]
name = "route-name"  # Optional: for logging/debugging
path_prefix = "/api/v1"  # Option 1: Simple prefix
# OR
path_regex = "^/api/v[12]/.*"  # Option 2: Regex pattern
backend = "127.0.0.1:8090"
strip_prefix = true  # Optional: Remove matched prefix when forwarding
timeout_seconds = 30  # Optional: Override global timeout

# Route-specific rules (merged with listener rules)
[[listener."name".routes.request_rules]]
name = "Route-specific rule"
action = "allow" | "deny"
# ... rule conditions ...

[[listener."name".routes.response_rules]]
name = "Route-specific rule"
action = "allow" | "deny"
# ... rule conditions ...
```

---

## 📝 Complete Example Configuration

```toml
# ═══════════════════════════════════════════════════════════
# GLOBAL SETTINGS
# ═══════════════════════════════════════════════════════════
[global]
log_level = "info"
timeout_seconds = 30

# ═══════════════════════════════════════════════════════════
# LISTENER 1: External API (Public Internet)
# ═══════════════════════════════════════════════════════════
[listener."external-api"]
ip = "10.10.1.10"
port = 8443
description = "Public-facing API with TLS"
default_action = "reject"  # Return 404 for unmatched routes

# TLS Configuration
[listener."external-api".tls]
enabled = true
cert_file = "/mnt/secure/cert/external/fullchain.pem"
key_file = "/mnt/secure/cert/external/privkey.pem"

# Listener-level rules (apply to ALL routes)
[[listener."external-api".request_rules]]
name = "Block dangerous methods globally"
action = "deny"
methods = ["TRACE", "TRACK", "DELETE"]

[[listener."external-api".request_rules]]
name = "Rate limit by requiring token"
action = "deny"
path_regex = "^/api/.*"
# Note: Will be overridden by route-specific allow rules

[[listener."external-api".response_rules]]
name = "Hide server errors from public"
action = "deny"
status_codes = [500, 501, 502, 503, 504]

# Route 1: API v1 → Component 1
[[listener."external-api".routes]]
name = "api-v1-users"
path_prefix = "/api/v1/users"
backend = "127.0.0.1:8090"
strip_prefix = true  # Backend receives /john instead of /api/v1/users/john
timeout_seconds = 15  # Faster timeout for this service

[[listener."external-api".routes.request_rules]]
name = "Require authentication"
action = "allow"
require_header = "Authorization"

[[listener."external-api".routes.request_rules]]
name = "Block unauthenticated"
action = "deny"

# Route 2: API v1 → Component 2  
[[listener."external-api".routes]]
name = "api-v1-posts"
path_prefix = "/api/v1/posts"
backend = "127.0.0.1:8091"
strip_prefix = true

[[listener."external-api".routes.request_rules]]
name = "Allow only GET and POST"
action = "allow"
methods = ["GET", "POST"]

[[listener."external-api".routes.request_rules]]
name = "Block other methods"
action = "deny"

# Route 3: API v2 → New Component (Regex matching)
[[listener."external-api".routes]]
name = "api-v2-all"
path_regex = "^/api/v2/.*"
backend = "127.0.0.1:8092"
strip_prefix = false  # Keep full path

[[listener."external-api".routes.request_rules]]
name = "Require API key header"
action = "allow"
require_header = "X-API-Key"

# Route 4: Health check (no auth required)
[[listener."external-api".routes]]
name = "health-check"
path_prefix = "/health"
backend = "127.0.0.1:8090"
strip_prefix = false

[[listener."external-api".routes.request_rules]]
name = "Allow health checks without auth"
action = "allow"
methods = ["GET"]

# ═══════════════════════════════════════════════════════════
# LISTENER 2: Internal Admin (Private Network)
# ═══════════════════════════════════════════════════════════
[listener."internal-admin"]
ip = "172.16.1.10"
port = 8080
description = "Internal admin interface (no TLS, trusted network)"
default_backend = "127.0.0.1:9090"  # Default admin backend
default_action = "forward"  # Forward unmatched to default_backend

# No TLS (internal network)
[listener."internal-admin".tls]
enabled = false

# Listener-level rules
[[listener."internal-admin".request_rules]]
name = "Block external access"
action = "deny"
# Note: In production, also use firewall rules!

# Route 1: Admin Dashboard
[[listener."internal-admin".routes]]
name = "admin-dashboard"
path_prefix = "/admin/dashboard"
backend = "127.0.0.1:9091"
strip_prefix = true

# Route 2: Admin API
[[listener."internal-admin".routes]]
name = "admin-api"
path_prefix = "/admin/api"
backend = "127.0.0.1:9092"
strip_prefix = true

[[listener."internal-admin".routes.request_rules]]
name = "Allow all methods for admin"
action = "allow"

# Route 3: Monitoring
[[listener."internal-admin".routes]]
name = "monitoring"
path_prefix = "/monitoring"
backend = "127.0.0.1:9093"
strip_prefix = true

# ═══════════════════════════════════════════════════════════
# LISTENER 3: Multi-tenant API
# ═══════════════════════════════════════════════════════════
[listener."multi-tenant"]
ip = "0.0.0.0"
port = 8000
description = "Multi-tenant API with path-based routing"
default_action = "reject"

[listener."multi-tenant".tls]
enabled = true
cert_file = "/mnt/secure/cert/multi/fullchain.pem"
key_file = "/mnt/secure/cert/multi/privkey.pem"

# Route by tenant ID (regex)
[[listener."multi-tenant".routes]]
name = "tenant-alpha"
path_regex = "^/tenant/alpha/.*"
backend = "127.0.0.1:8100"
strip_prefix = false  # Keep tenant ID in path

[[listener."multi-tenant".routes.request_rules]]
name = "Require tenant alpha token"
action = "allow"
require_header = "X-Tenant-Token"

[[listener."multi-tenant".routes]]
name = "tenant-beta"
path_regex = "^/tenant/beta/.*"
backend = "127.0.0.1:8101"
strip_prefix = false

[[listener."multi-tenant".routes.request_rules]]
name = "Require tenant beta token"
action = "allow"
require_header = "X-Tenant-Token"

# ═══════════════════════════════════════════════════════════
# LISTENER 4: Microservices Gateway
# ═══════════════════════════════════════════════════════════
[listener."microservices-gateway"]
ip = "192.168.1.100"
port = 8080
description = "Internal microservices gateway"
default_action = "reject"

[listener."microservices-gateway".tls]
enabled = false  # Internal network

# Route to different microservices
[[listener."microservices-gateway".routes]]
name = "auth-service"
path_prefix = "/auth"
backend = "127.0.0.1:8200"
strip_prefix = true
timeout_seconds = 10

[[listener."microservices-gateway".routes]]
name = "user-service"
path_prefix = "/users"
backend = "127.0.0.1:8201"
strip_prefix = true

[[listener."microservices-gateway".routes]]
name = "payment-service"
path_prefix = "/payments"
backend = "127.0.0.1:8202"
strip_prefix = true

[[listener."microservices-gateway".routes.request_rules]]
name = "Block large payments"
action = "deny"
path_regex = ".*/amount/[5-9][0-9]{4,}.*"  # Amounts >= 50000

[[listener."microservices-gateway".routes]]
name = "notification-service"
path_prefix = "/notifications"
backend = "127.0.0.1:8203"
strip_prefix = true
```

---

## 🔍 Configuration Validation Rules

### Listener Level
1. ✅ Each listener must have unique `(ip, port)` combination
2. ✅ `default_action = "forward"` requires `default_backend` to be set
3. ✅ If TLS enabled, both `cert_file` and `key_file` must be set
4. ✅ Certificate files must exist and be readable

### Route Level
1. ✅ Each route must have either `path_prefix` OR `path_regex` (not both)
2. ✅ Routes are evaluated in order (first match wins)
3. ✅ `backend` must be valid address:port format
4. ✅ If `strip_prefix = true`, must use `path_prefix` (not `path_regex`)
5. ✅ Route names should be unique within a listener (for clarity)

### Rule Level
1. ✅ Rules evaluated: Listener rules first, then route rules
2. ✅ First matching rule wins
3. ✅ If no rules match, default is ALLOW
4. ✅ `path_regex` in rules uses same regex engine as route matching

---

## 🎯 Rule Evaluation Flow

```
Client Request: GET /api/v1/users/123
       ↓
┌──────────────────────────────────────────────┐
│ 1. Match Listener (ip:port)                 │
│    → "external-api" (10.10.1.10:8443)       │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 2. Evaluate Listener-Level Request Rules    │
│    → Check "Block dangerous methods"        │
│    → Check "Rate limit"                     │
│    → Result: Continue (no deny)             │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 3. Match Route (prefix/regex)               │
│    → Check "/api/v1/users" prefix           │
│    → Match! → backend = 127.0.0.1:8090      │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 4. Evaluate Route-Level Request Rules       │
│    → Check "Require authentication"         │
│    → Result: Allow (has Authorization)      │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 5. Apply Path Rewriting                     │
│    → Original: /api/v1/users/123            │
│    → strip_prefix = true                    │
│    → Rewritten: /123                        │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 6. Forward to Backend                       │
│    → Connect to 127.0.0.1:8090              │
│    → Send: GET /123 HTTP/1.1                │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 7. Receive Response from Backend            │
│    → HTTP/1.1 200 OK                        │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 8. Evaluate Listener-Level Response Rules   │
│    → Check "Hide server errors"             │
│    → Result: Continue (200 OK)              │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 9. Evaluate Route-Level Response Rules      │
│    → (None defined for this route)          │
│    → Result: Allow                          │
└──────────────────┬───────────────────────────┘
                   ↓
┌──────────────────────────────────────────────┐
│ 10. Return to Client                        │
│     → Encrypt with TLS                      │
│     → Send response                         │
└──────────────────────────────────────────────┘
```

---

## 🔄 Migration Guide

### From Current Config to New Config

**Old (Single Listener):**
```toml
[proxy]
listen_address = "0.0.0.0:8080"
backend_address = "127.0.0.1:9090"
timeout_seconds = 30

[tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"

[[request_rules]]
name = "Block admin"
action = "deny"
path_regex = "^/admin/.*"
```

**New (Multi-Listener):**
```toml
[global]
timeout_seconds = 30

[listener."default"]
ip = "0.0.0.0"
port = 8080
default_backend = "127.0.0.1:9090"
default_action = "forward"

[listener."default".tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"

[[listener."default".request_rules]]
name = "Block admin"
action = "deny"
path_regex = "^/admin/.*"
```

---

## 📊 Example Use Cases

### Use Case 1: API Gateway with Version Routing

```toml
[listener."api-gateway"]
ip = "0.0.0.0"
port = 443
default_action = "reject"

[listener."api-gateway".tls]
enabled = true
cert_file = "/etc/certs/api.pem"
key_file = "/etc/certs/api-key.pem"

# V1 API (legacy) → Old backend
[[listener."api-gateway".routes]]
name = "api-v1"
path_prefix = "/api/v1"
backend = "127.0.0.1:8001"
strip_prefix = true

# V2 API (current) → New backend
[[listener."api-gateway".routes]]
name = "api-v2"
path_prefix = "/api/v2"
backend = "127.0.0.1:8002"
strip_prefix = true

# V3 API (beta) → Beta backend with stricter rules
[[listener."api-gateway".routes]]
name = "api-v3"
path_prefix = "/api/v3"
backend = "127.0.0.1:8003"
strip_prefix = true

[[listener."api-gateway".routes.request_rules]]
name = "Require beta access"
action = "allow"
require_header = "X-Beta-Access"
```

### Use Case 2: Multi-Region Load Balancer

```toml
# US East listener
[listener."us-east"]
ip = "10.1.1.10"
port = 8080

[[listener."us-east".routes]]
name = "default"
path_prefix = "/"
backend = "10.1.1.100:8080"  # US East backend
strip_prefix = false

# US West listener
[listener."us-west"]
ip = "10.2.1.10"
port = 8080

[[listener."us-west".routes]]
name = "default"
path_prefix = "/"
backend = "10.2.1.100:8080"  # US West backend
strip_prefix = false

# EU listener
[listener."eu-central"]
ip = "10.3.1.10"
port = 8080

[[listener."eu-central".routes]]
name = "default"
path_prefix = "/"
backend = "10.3.1.100:8080"  # EU backend
strip_prefix = false
```

### Use Case 3: Development vs Production

```toml
# Development (no TLS, relaxed rules)
[listener."dev"]
ip = "127.0.0.1"
port = 8080
default_backend = "127.0.0.1:9090"
default_action = "forward"

[listener."dev".tls]
enabled = false

[[listener."dev".request_rules]]
name = "Allow all"
action = "allow"

# Production (TLS, strict rules)
[listener."prod"]
ip = "0.0.0.0"
port = 443
default_action = "reject"

[listener."prod".tls]
enabled = true
cert_file = "/etc/letsencrypt/live/api.example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/api.example.com/privkey.pem"

[[listener."prod".request_rules]]
name = "Require authentication"
action = "deny"
# (Then specific routes allow with auth)
```

---

## 🎨 Configuration Best Practices

### 1. Naming Conventions
```toml
# Good: Descriptive names
[listener."public-api-https"]
[listener."internal-admin-http"]
[listener."legacy-v1-gateway"]

# Avoid: Generic names
[listener."listener1"]
[listener."test"]
```

### 2. Security Layers
```toml
# Layer 1: Listener-level (applies to all routes)
[[listener."api".request_rules]]
name = "Block dangerous methods globally"
action = "deny"
methods = ["TRACE", "TRACK"]

# Layer 2: Route-level (specific to each route)
[[listener."api".routes.request_rules]]
name = "Require auth for this route"
action = "allow"
require_header = "Authorization"
```

### 3. Path Organization
```toml
# Organize routes from most specific to least specific
# (if you ever need overlapping patterns)

# More specific
[[listener."api".routes]]
path_prefix = "/api/v1/admin/users"
backend = "127.0.0.1:8001"

# Less specific
[[listener."api".routes]]
path_prefix = "/api/v1/admin"
backend = "127.0.0.1:8002"

# Least specific
[[listener."api".routes]]
path_prefix = "/api/v1"
backend = "127.0.0.1:8003"
```

### 4. Default Actions
```toml
# Public-facing: Reject unknown routes (security)
[listener."public"]
default_action = "reject"

# Internal: Forward to default backend (convenience)
[listener."internal"]
default_backend = "127.0.0.1:9090"
default_action = "forward"
```

---

## 📏 Size Recommendations

**For typical deployments:**
- Small: 1-2 listeners, 3-5 routes each
- Medium: 3-5 listeners, 5-10 routes each
- Large: 5-10 listeners, 10-20 routes each

**Performance:**
- ✅ Route matching is O(n) per listener
- ✅ Keep routes per listener < 50 for best performance
- ✅ Use prefix matching when possible (faster than regex)



