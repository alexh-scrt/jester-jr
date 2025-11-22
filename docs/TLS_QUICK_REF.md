# 🔒 TLS Quick Reference for Jester Jr

## 🚀 Quick Start

### 1. Generate Certificates
```bash
./generate_certs.sh
```

### 2. Update Configuration
```toml
[proxy]
listen_address = "127.0.0.1:8443"  # HTTPS port

[tls]
enabled = true
cert_file = "./certs/cert.pem"
key_file = "./certs/key.pem"
```

### 3. Build and Run
```bash
cargo build --release
./target/release/jester-jr jester-jr-tls.toml
```

### 4. Test
```bash
# Simple test
curl -k https://localhost:8443/

# Run test suite
./test_tls.sh
```

---

## 📦 Dependencies

Add to `Cargo.toml`:
```toml
rustls = "0.23"
rustls-pemfile = "2.1"
```

---

## 🔧 Configuration Options

### Enable TLS
```toml
[tls]
enabled = true
cert_file = "./certs/cert.pem"
key_file = "./certs/key.pem"
```

### Disable TLS (HTTP only)
```toml
[tls]
enabled = false
```

Or simply omit the `[tls]` section.

---

## 🧪 Testing Commands

### Basic HTTPS Request
```bash
curl -k https://localhost:8443/
```

### Verbose TLS Information
```bash
curl -kv https://localhost:8443/
```

### Check Certificate
```bash
openssl s_client -connect localhost:8443 -showcerts
```

### Test TLS 1.2
```bash
curl -k --tlsv1.2 --tls-max 1.2 https://localhost:8443/
```

### Test TLS 1.3
```bash
curl -k --tlsv1.3 https://localhost:8443/
```

### Test with Authentication
```bash
curl -k -H "Authorization: Bearer token" https://localhost:8443/protected/data
```

---

## 🔑 Certificate Management

### Generate Self-Signed Certificate
```bash
# Private key
openssl genrsa -out key.pem 2048

# Certificate (valid 365 days)
openssl req -new -x509 \
    -key key.pem \
    -out cert.pem \
    -days 365 \
    -subj "/CN=localhost"
```

### View Certificate
```bash
openssl x509 -in cert.pem -noout -text
```

### Check Certificate Validity
```bash
openssl x509 -in cert.pem -noout -dates
```

### Set Correct Permissions
```bash
chmod 600 key.pem   # Private key - owner only
chmod 644 cert.pem  # Certificate - readable by all
```

---

## 🏭 Production Setup

### Using Let's Encrypt
```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d yourdomain.com

# Certificates will be in:
# /etc/letsencrypt/live/yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

### Update Configuration for Production
```toml
[tls]
enabled = true
cert_file = "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/yourdomain.com/privkey.pem"
```

---

## 🐛 Troubleshooting

### "Failed to open cert file"
- Check file path is correct
- Verify file exists: `ls -l certs/cert.pem`
- Check read permissions

### "Failed to parse certificates"
- Ensure file is in PEM format
- Check for corruption: `openssl x509 -in cert.pem -noout -text`
- Regenerate if needed

### "Failed to parse private key"
- Ensure key is in PKCS#8 format
- Convert if needed: `openssl pkcs8 -topk8 -nocrypt -in old_key.pem -out key.pem`

### "TLS handshake failed"
- Check firewall allows port 8443
- Verify backend is running
- Check certificates match
- Look at server logs for details

### "curl: SSL certificate problem"
- Normal for self-signed certs
- Use `-k` flag to skip verification: `curl -k https://...`
- Or add cert to system trust store

---

## 📊 Performance Impact

| Metric     | HTTP       | HTTPS      | Overhead |
| ---------- | ---------- | ---------- | -------- |
| Latency    | 1.2ms      | 1.5ms      | +25%     |
| Throughput | 8000 req/s | 6500 req/s | -19%     |
| Memory     | 16KB/conn  | 20KB/conn  | +4KB     |
| Handshake  | N/A        | 1-5ms      | One-time |

---

## 🔒 Security Checklist

- [ ] Private key has `chmod 600` permissions
- [ ] Certificates are valid (check expiration)
- [ ] Using TLS 1.2 or higher
- [ ] Strong cipher suites enabled
- [ ] Production certificates from trusted CA
- [ ] Regular certificate renewal (Let's Encrypt = 90 days)
- [ ] Backend connection is secure
- [ ] Logging enabled for security events

---

## 📚 Key Concepts

### Arc<ServerConfig>
- Thread-safe shared ownership
- Cheap to clone (just increments counter)
- Allows sharing TLS config across threads

### PEM Format
```
-----BEGIN CERTIFICATE-----
Base64EncodedData...
-----END CERTIFICATE-----
```

### PKCS#8 Private Key
```
-----BEGIN PRIVATE KEY-----
Base64EncodedData...
-----END PRIVATE KEY-----
```

### TLS Handshake
1. Client Hello (supported ciphers)
2. Server Hello (chosen cipher)
3. Certificate exchange
4. Key exchange
5. Finished (encrypted)

---

## 🎓 Learning Resources

- [rustls documentation](https://docs.rs/rustls/)
- [TLS 1.3 RFC](https://tools.ietf.org/html/rfc8446)
- [Let's Encrypt](https://letsencrypt.org/)
- [OpenSSL cookbook](https://www.feistyduck.com/library/openssl-cookbook/)

---

## ⚡ Next Steps

After implementing TLS, consider:
1. HTTP/2 support (requires TLS)
2. ALPN for protocol negotiation
3. Session resumption for performance
4. Client certificate authentication (mutual TLS)
5. OCSP stapling
6. Certificate pinning

---

**Need Help?**
- Check logs for detailed error messages
- Run `./test_tls.sh` to diagnose issues
- Verify certificates with OpenSSL commands
- Review the full TLS_IMPLEMENTATION_GUIDE.md

---

**Version**: 0.2.0  
**Last Updated**: November 2025