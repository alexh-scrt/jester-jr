# TLS Reader Implementation Notes

## Issue: WouldBlock Errors in TLS Connection Handling

### Problem Description
The `TlsReader` implementation was immediately failing with `WouldBlock` errors when trying to read HTTP request data after a successful TLS handshake, causing all HTTPS requests to fail with "400 Bad Request".

### Root Cause Analysis

#### What Was Happening
1. TLS handshake completed successfully ✅
2. Client (curl) sent encrypted HTTP request data ✅
3. `BufRead::read_line()` called `TlsReader::fill_buf()` ✅
4. `conn.reader().read()` returned `WouldBlock` (no decrypted data available) ❌
5. **CRITICAL**: Original code immediately returned `WouldBlock` error instead of reading more TLS data ❌

#### Why It Failed
The original `fill_buf()` implementation had flawed error handling:

```rust
// BROKEN - Original implementation
match self.conn.reader().read(&mut temp_buf) {
    Ok(n) if n > 0 => { /* ... */ }
    Ok(_) => {
        // Only tried to read more TLS data in this case
        match self.conn.read_tls(&mut self.stream) { /* ... */ }
    }
    Err(e) => return Err(e), // ❌ IMMEDIATE FAILURE - No TLS data reading attempt!
}
```

When `conn.reader().read()` returns `WouldBlock`, it means:
- No decrypted application data is currently available in the TLS connection's internal buffer
- **But** encrypted data might be waiting in the TCP socket that needs to be read and decrypted
- The fix requires calling `read_tls()` to fetch and decrypt more data

### Solution Implementation

#### Fixed Error Handling
```rust
// FIXED - New implementation  
match self.conn.reader().read(&mut temp_buf) {
    Ok(n) if n > 0 => { /* ... */ }
    Ok(_) => {
        // No decrypted data, read more TLS data
        match self.conn.read_tls(&mut self.stream) { /* ... */ }
    }
    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
        // ✅ PROPER FIX: Also read more TLS data on WouldBlock
        match self.conn.read_tls(&mut self.stream) {
            Ok(0) => return Ok(&[]), // Connection closed
            Ok(_) => {
                // Process decrypted packets and retry
                self.conn.process_new_packets()?;
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Truly no data available, wait and retry
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(e) => return Err(e),
}
```

#### Additional Improvements
1. **Added proper timeouts** to prevent infinite blocking
2. **Added comprehensive debug logging** to trace TLS data flow
3. **Added WouldBlock handling** in both `Read` and `BufRead` implementations
4. **Added explicit flush** in TLS handshake to ensure immediate data transmission

### Key Lessons Learned

#### TLS Data Flow Understanding
```
Client TCP Socket → [Encrypted Data] → read_tls() → process_new_packets() → conn.reader().read() → [Decrypted Data] → Application
```

- `read_tls()`: Reads encrypted bytes from TCP socket
- `process_new_packets()`: Decrypts the bytes and stores in internal buffer  
- `conn.reader().read()`: Reads decrypted application data from internal buffer

#### Critical TLS Reader Requirements
1. **Never ignore WouldBlock on `conn.reader().read()`** - Always attempt to read more TLS data
2. **Always call `process_new_packets()`** after successful `read_tls()`
3. **Implement proper timeouts** to avoid infinite loops
4. **Handle WouldBlock at multiple levels** - both TLS layer and application layer

#### Common Mistakes to Avoid
1. ❌ Returning `WouldBlock` immediately without attempting `read_tls()`
2. ❌ Not calling `process_new_packets()` after reading TLS data  
3. ❌ Infinite retry loops without timeouts
4. ❌ Assuming TLS handshake completion means data is immediately available

### Testing Verification

#### Working Behavior
```bash
curl -v https://example.com:8080/test
```

**Expected Logs:**
```
INFO  TLS handshake complete with X.X.X.X:XXXX
DEBUG Starting HTTP request parse
DEBUG TLS fill_buf starting, waiting for data...
DEBUG TLS fill_buf conn.reader() WouldBlock, reading more TLS data...
DEBUG TLS fill_buf got 123 bytes of data
INFO  📥 GET /test [listener-name] (TLS)
```

#### Failure Indicators
- Immediate `WouldBlock` errors without retry attempts
- Missing "reading more TLS data" logs
- Timeout errors when client tools show successful TLS handshake

### Related Code Files
- `src/main.rs`: `TlsReader` implementation (lines ~1350-1505)
- `src/parsers/request.rs`: HTTP request parsing
- `src/tls/mod.rs`: TLS configuration

### Performance Considerations
- 10ms sleep intervals in retry loops prevent excessive CPU usage
- 5-second timeouts balance responsiveness vs compatibility
- Debug logging can be disabled in production for performance

---

**Date**: November 23, 2025  
**Issue**: TLS WouldBlock handling  
**Resolution**: Proper TLS data flow implementation with comprehensive error handling