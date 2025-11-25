# 🃏 Jester Jr - Production-Ready Rust Reverse Proxy

![Logo](./imgs/jester-jr.png)

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](src/config.rs)
[![Release](https://img.shields.io/badge/release-v0.1.0-success.svg)](https://github.com/alexh-scrt/jester-jr/releases)

🎉 **v0.1.0 Now Available!** A production-ready HTTP reverse proxy built from scratch in Rust, featuring multi-listener architecture, TLS/HTTPS support, comprehensive validation framework, IP blacklisting, and advanced request/response filtering.

## ✨ Features (v0.1.0)

### 🏗️ **Multi-Listener Architecture**
- 🌐 **Multiple Listeners** - Run HTTP/HTTPS/Admin/Dev servers simultaneously
- 🔧 **Per-Listener Configuration** - Different rules and backends per listener
- 🎯 **Path-Based Routing** - Route requests by URL patterns to different backends
- ✂️ **Path Rewriting** - Strip prefixes for clean backend routing
- 📋 **Default Actions** - Configure reject vs forward behavior for unmatched routes

### 🔒 **Security & Validation Framework**
- 🛡️ **IP Blacklisting** - Automatic and manual IP blocking with TTL expiry
- 🔑 **Built-in Validators** - API key, JWT, and Jester-Secret authentication
- 📜 **Custom Script Validators** - Rhai scripting engine for custom validation logic
- 🚫 **TLS Failure Tracking** - Automatic blacklisting of problematic TLS connections
- 🔐 **Header-Based Security** - Flexible authentication and authorization

### 🌐 **TLS/HTTPS Support**
- 🔒 **Per-Listener TLS** - Configure different certificates for different listeners
- 📜 **Certificate Management** - PEM format certificate and private key support
- 🛡️ **TLS Error Handling** - Graceful handling of TLS handshake failures
- 🔧 **Mixed Protocol** - HTTP and HTTPS listeners on the same instance

### 📊 **Advanced Request/Response Processing**
- 🔄 **Bidirectional Streaming** - Concurrent request and response streaming
- 🚀 **Zero-Copy Body Transfer** - Efficient memory usage with constant 8KB buffers
- 📊 **Full HTTP Parsing** - Complete request and response header parsing
- ⏱️ **Hierarchical Timeouts** - Global, listener, and route-specific timeouts
- 🛡️ **Robust Error Handling** - Graceful degradation, no panics

### 🔍 **Comprehensive Filtering**
- 🎯 **Path Matching** - Prefix and regex-based URL filtering
- 🔐 **Header Requirements** - Enforce authentication and custom headers
- 🚫 **Method Filtering** - Control allowed HTTP methods per route
- 📏 **Response Size Limits** - Prevent bandwidth exhaustion attacks
- 🔢 **Status Code Filtering** - Hide backend errors from clients
- ⚙️ **TOML Configuration** - Human-readable configuration with validation

## 🚀 Quick Start

### Prerequisites
- Rust 1.75 or newer
- Cargo (comes with Rust)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/jester-jr
cd jester-jr

# Build release version
cargo build --release

# Run with default config
./target/release/jester-jr
```

### v0.1.0 Configuration Example

Create `jester-jr.toml` with the new multi-listener architecture:

```toml
[global]
log_level = "info"
timeout_seconds = 30
blacklist_file = "./data/blacklist.json"

# API key validator
[validators.api_key]
type = "builtin"
config = { valid_keys = ["your-api-key-here"], header_name = "x-api-key" }

# HTTP listener
[listener."main"]
ip = "127.0.0.1"
port = 8080
description = "Main HTTP API"
default_action = "reject"

# Public API route with authentication
[[listener."main".routes]]
name = "public-api"
path_prefix = "/api"
backend = "127.0.0.1:9090"
strip_prefix = true

[[listener."main".routes.validators]]
validator = "api_key"
on_failure = "deny"

# Health check route (no auth)
[[listener."main".routes]]
name = "health"
path_prefix = "/health"
backend = "127.0.0.1:9090"
```

### Testing v0.1.0

```bash
# 1. Start backend server
python3 ./backend_server.py &

# 2. Start Jester Jr
./target/release/jester-jr jester-jr.toml &

# 3. Test authenticated endpoint
curl -H "x-api-key: your-api-key-here" http://localhost:8080/api/users

# 4. Test health check (no auth required)
curl http://localhost:8080/health

# 5. Run comprehensive test suite
./curl_tests.sh
```

## 📖 Documentation

### v0.1.0 Documentation
- **[USAGE.md](docs/USAGE.md)** - Comprehensive usage guide with examples
- **[MULTI_LISTENER_CONFIG_DESIGN.md](docs/MULTI_LISTENER_CONFIG_DESIGN.md)** - Multi-listener architecture guide
- **[CONFIG_FILTERING.md](docs/CONFIG_FILTERING.md)** - Advanced filtering configuration
- **[TLS_QUICK_REF.md](docs/TLS_QUICK_REF.md)** - TLS/HTTPS setup guide
- **[ROADMAP.md](docs/ROADMAP.md)** - Future development plans

### Testing & Examples
- **[test-config-aligned.toml](test-config-aligned.toml)** - Complete example configuration
- **[curl_tests.sh](curl_tests.sh)** - Comprehensive test suite
- **[backend_server.py](backend_server.py)** - Test backend server

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Client                               │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP Request
                           ▼
┌────────────────────────────────────────────────────────────┐
│                      Jester Jr Proxy                       │
│                                                            │
│  ┌────────────────────────────────────────────────────┐    │
│  │ 1. Parse Request Headers                           │    │
│  │    • Method, Path, Version                         │    │
│  │    • All Headers (case-insensitive)                │    │
│  │    • Content-Length detection                      │    │
│  └────────────────────────────────────────────────────┘    │
│                           ↓                                │
│  ┌────────────────────────────────────────────────────┐    │
│  │ 2. Evaluate Request Rules (First Match Wins)       │    │
│  │    • Path regex matching                           │    │
│  │    • Method filtering                              │    │
│  │    • Header requirements                           │    │
│  │    • Action: Allow or Deny                         │    │
│  └────────────────────────────────────────────────────┘    │
│                           ↓                                │
│  ┌────────────────────────────────────────────────────┐    │
│  │ 3. Forward Headers to Backend                      │    │
│  └────────────────────────────────────────────────────┘    │
│                           ↓                                │
│  ┌────────────────────────────────────────────────────┐    │
│  │ 4. Bidirectional Streaming                         │    │
│  │    Thread 1: Client → Backend (Request Body)       │    │
│  │    Thread 2: Backend → Client (Response)           │    │
│  └────────────────────────────────────────────────────┘    │
│                           ↓                                │
│  ┌────────────────────────────────────────────────────┐    │
│  │ 5. Parse Response Headers                          │    │
│  │    • Status Code, Status Text                      │    │
│  │    • All Headers                                   │    │
│  │    • Content-Length detection                      │    │
│  └────────────────────────────────────────────────────┘    │
│                           ↓                                │
│  ┌────────────────────────────────────────────────────┐    │
│  │ 6. Evaluate Response Rules                         │    │
│  │    • Status code filtering                         │    │
│  │    • Size limit checks                             │    │
│  │    • Action: Allow or Deny                         │    │
│  └────────────────────────────────────────────────────┘    │
│                           ↓                                │
│  ┌────────────────────────────────────────────────────┐    │
│  │ 7. Stream Response Body to Client                  │    │
│  └────────────────────────────────────────────────────┘    │
└──────────────────────────┬─────────────────────────────────┘
                           │ HTTP Response
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                        Client                               │
└─────────────────────────────────────────────────────────────┘
```

## 📊 Performance

| Metric                 | Value        | Notes                           |
| ---------------------- | ------------ | ------------------------------- |
| Filtering Overhead     | <1ms         | Per request, with 10-20 rules   |
| Memory per Connection  | ~16KB        | 2x 8KB buffers                  |
| Thread per Request     | 1 (for body) | Only if request has body        |
| Regex Compilation      | Startup only | Pre-compiled, zero runtime cost |
| Concurrent Connections | OS-limited   | Thread per connection model     |

## 🎯 Use Cases

### Development & Testing
- Local API gateway for microservices
- Request/response inspection and logging
- Testing authentication flows
- Rate limiting (planned)

### Production Scenarios
- Simple API gateway
- Path-based routing
- Method whitelisting for security
- Error response filtering
- Content size enforcement

### Security Applications
- Block admin/sensitive paths
- Enforce authentication headers
- Hide backend error details
- Prevent large response attacks

## 🔧 Configuration

### Basic Setup

```toml
[proxy]
listen_address = "127.0.0.1:8080"    # Proxy listen address
backend_address = "127.0.0.1:9090"   # Backend server address
timeout_seconds = 30                  # Connection timeout
```

### Request Filtering Examples

```toml
# Block admin paths
[[request_rules]]
name = "Block admin access"
action = "deny"
path_regex = "^/admin/.*"

# Require authentication for protected paths
[[request_rules]]
name = "Protected paths with auth"
action = "allow"
path_regex = "^/protected/.*"
require_header = "Authorization"

[[request_rules]]
name = "Protected paths without auth"
action = "deny"
path_regex = "^/protected/.*"

# Method whitelisting
[[request_rules]]
name = "Read-only API"
action = "allow"
path_regex = "^/api/.*"
methods = ["GET", "HEAD", "OPTIONS"]
```

### Response Filtering Examples

```toml
# Hide backend errors
[[response_rules]]
name = "Block server errors"
action = "deny"
status_codes = [500, 501, 502, 503, 504]

# Limit response size
[[response_rules]]
name = "Block large responses"
action = "deny"
max_size_bytes = 10485760  # 10 MB
```

See [USAGE.md](USAGE.md) for complete configuration guide.

## 🧪 Testing v0.1.0

### Automated Test Suite

```bash
# 1. Build the project
cargo build --release

# 2. Start backend server (Terminal 1)
python3 ./backend_server.py

# 3. Start Jester Jr (Terminal 2)
./target/release/jester-jr test-config-aligned.toml

# 4. Run comprehensive tests (Terminal 3)
./curl_tests.sh
```

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run with output
cargo test -- --nocapture

# Test specific modules
cargo test config::tests
cargo test validators::tests
```

### Test Coverage
- ✅ **Multi-listener configuration** - All listener types and routing
- ✅ **Validator framework** - API key, JWT, Jester-Secret validation
- ✅ **TLS/HTTPS support** - Certificate handling and secure connections
- ✅ **Path routing** - Prefix matching, regex patterns, path rewriting
- ✅ **Request filtering** - Method filtering, header requirements
- ✅ **Response filtering** - Status codes, size limits
- ✅ **IP blacklisting** - Manual and automatic TLS-failure tracking
- ✅ **Configuration validation** - Syntax checking and error handling

**Test Results: 20+ integration tests + comprehensive unit test suite**

## 📦 Dependencies v0.1.0

```toml
[dependencies]
# Core functionality
serde = { version = "1.0", features = ["derive"] }
toml = "0.9.8"
regex = "1.10"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }

# TLS/HTTPS support
rustls = "0.23"
rustls-pemfile = "2.1"

# Validator framework
rhai = { version = "1.19", features = ["sync", "serde"] }  # Scripting engine
wasmtime = "27.0"                                          # WASM runtime
serde_json = "1.0"
async-trait = "0.1"
parking_lot = "0.12"
tokio = { version = "1.0", features = ["rt", "macros"] }

# Built-in validators
jsonwebtoken = "9.3"  # JWT validation
base64 = "0.22"
chrono = "0.4"
```

All dependencies are production-ready, well-maintained crates from the Rust ecosystem.


## 🗺️ Roadmap

**Current Version: 0.1.0 - Production-Ready Multi-Listener Proxy** ✅

### ✅ **Released in v0.1.0:**
- ✅ Multi-listener architecture with path-based routing
- ✅ TLS/HTTPS support with per-listener certificates
- ✅ Comprehensive validator framework (API key, JWT, Jester-Secret)
- ✅ IP blacklisting with automatic TLS failure tracking
- ✅ Advanced request/response filtering
- ✅ Complete test suite and documentation

### 🚧 **Planned for v0.2.0:**
- [ ] Rate limiting per IP/path/endpoint
- [ ] Load balancing across multiple backend servers
- [ ] Health checks with automatic failover
- [ ] Prometheus metrics endpoint
- [ ] Hot config reload without restart

### 🔮 **Future Versions:**
- [ ] WebSocket proxying support
- [ ] Request/response transformation and middleware
- [ ] Redis-based session management
- [ ] Advanced monitoring and alerting

See [docs/ROADMAP.md](docs/ROADMAP.md) for detailed development timeline.

## 🤝 Contributing

Contributions are welcome! This is a learning project, so feel free to:
- Add features from the roadmap
- Improve documentation
- Add more tests
- Optimize performance
- Report bugs or suggest improvements

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

Built as a hands-on learning project to master Rust fundamentals through practical implementation of a production-grade reverse proxy.

Special thanks to:
- The Rust community for excellent documentation
- The authors of `serde`, `toml`, and `regex` crates
- Everyone who provides feedback and suggestions

## 📞 Support

- 📖 **Documentation**: See docs in this repository
- 🐛 **Bug Reports**: Open an issue on GitHub
- 💡 **Feature Requests**: Open an issue with the "enhancement" label
- 💬 **Questions**: Open a discussion on GitHub

## 🌟 Star History

If you find this project useful for learning Rust or as a lightweight proxy solution, please consider giving it a star!

---

## 🎉 **v0.1.0 Release Highlights**

### What's New:
- 🏗️ **Complete architectural overhaul** to multi-listener design
- 🔒 **Production-grade security** with comprehensive validation framework
- 🌐 **TLS/HTTPS support** with flexible certificate management
- 🛡️ **Advanced IP blacklisting** including automatic TLS failure tracking
- 🎯 **Intelligent routing** with path rewriting and backend selection
- 🧪 **Comprehensive testing** with 20+ integration tests and full automation

### Migration from v0.0.x:
Existing configurations are **automatically migrated** to the new format. See [docs/MULTI_LISTENER_CONFIG_DESIGN.md](docs/MULTI_LISTENER_CONFIG_DESIGN.md) for details.

---

**Status**: Production-Ready ✅ | **Release**: v0.1.0 ✅ | **Tests**: 20+ Passing ✅ | **Docs**: Complete ✅

Built with ❤️ and 🦀 Rust | Ready for production deployment! 🚀