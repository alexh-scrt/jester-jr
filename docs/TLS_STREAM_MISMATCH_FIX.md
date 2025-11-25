# TLS Stream Mismatch and WouldBlock Handler Fix

## Issue Description

After adding validator functionality to the jester-jr reverse proxy, HTTPS requests stopped being forwarded to backend servers. The TLS handshake completed successfully, but the HTTP request parsing would timeout with `TLS fill_buf timeout - no data received` errors.

### Error Logs
```
INFO  TLS handshake complete with X.X.X.X:XXXX
DEBUG Starting HTTP request parse
DEBUG TLS fill_buf starting, waiting for data...
DEBUG TLS fill_buf timeout after 5.000264736s
WARN  Error reading headers, error: Custom { kind: TimedOut, error: "TLS fill_buf timeout - no data received" }
WARN  Failed to parse TLS request: Error reading headers: TLS fill_buf timeout - no data received
```

## Root Cause Analysis

The issue was caused by **two separate bugs** that compounded each other:

### 1. TLS Stream Mismatch

**Problem**: The TLS handshake was performed using a cloned stream (`client_stream_clone`), but the `TlsReader` was created with the original stream (`client_stream`).

```rust
// BROKEN - Handshake on clone, reader on original
let mut client_stream_clone = client_stream.try_clone()?;

// Handshake performed on clone
match tls_conn.read_tls(&mut client_stream_clone) { /* ... */ }

// But TlsReader created with original stream
let mut tls_reader = TlsReader {
    conn: tls_conn,
    stream: client_stream,  // ❌ Wrong stream!
    buffer: Vec::new(),
    buffer_pos: 0,
};
```

**Why it failed**: The TLS connection object maintained internal state from reading encrypted data from `client_stream_clone` during handshake, but when `TlsReader` tried to read more TLS data, it was attempting to read from the original `client_stream`, which didn't have the same TLS state.

### 2. Incorrect WouldBlock Handler

**Problem**: There was a duplicate/incorrect `WouldBlock` error handler in the `fill_buf()` method that was interfering with proper TLS data flow.

```rust
// BROKEN - Early WouldBlock handler
match self.conn.reader().read(&mut temp_buf) {
    Ok(n) if n > 0 => { /* ... */ }
    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
        std::thread::sleep(std::time::Duration::from_millis(1));
        continue;  // ❌ Just sleeps, doesn't attempt read_tls()!
    }
    Ok(_) => {
        // Proper TLS data reading logic here...
    }
    // ... proper WouldBlock handling further down
}
```

**Why it failed**: When `conn.reader().read()` returned `WouldBlock` (meaning no decrypted data available), the incorrect handler just slept for 1ms and continued the loop without attempting to read more encrypted TLS data from the socket. This created an infinite loop that eventually timed out.

## Solution Implementation

### Fix 1: Correct Stream Usage

Changed `TlsReader` to use the same stream that was used for the handshake:

```rust
// FIXED - Use the same stream for both handshake and reader
let mut client_stream_clone = client_stream.try_clone()?;

// Handshake performed on clone
match tls_conn.read_tls(&mut client_stream_clone) { /* ... */ }

// TlsReader now uses the same stream
let mut tls_reader = TlsReader {
    conn: tls_conn,
    stream: client_stream_clone,  // ✅ Correct stream!
    buffer: Vec::new(),
    buffer_pos: 0,
};
```

### Fix 2: Remove Incorrect WouldBlock Handler

Removed the early `WouldBlock` handler that was bypassing proper TLS data reading:

```rust
// FIXED - Removed incorrect early handler
match self.conn.reader().read(&mut temp_buf) {
    Ok(n) if n > 0 => { /* ... */ }
    // ✅ Removed incorrect early WouldBlock handler
    Ok(_) => {
        // Need more TLS data
        match self.conn.read_tls(&mut self.stream) { /* ... */ }
    }
    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
        // ✅ Proper WouldBlock handling - attempts read_tls()
        debug!("TLS fill_buf conn.reader() WouldBlock, reading more TLS data...");
        match self.conn.read_tls(&mut self.stream) { /* ... */ }
    }
    Err(e) => return Err(e),
}
```

### Fix 3: Correct Error Response Handling

Updated error response code to work with the corrected stream ownership and avoid borrowing conflicts:

```rust
// FIXED - Direct access to avoid borrowing issues
let _ = tls_reader.conn.writer().write_all(response.as_bytes());
let _ = tls_reader.conn.write_tls(&mut tls_reader.stream);
```

## Key Lessons Learned

### TLS Stream Consistency
- **Always use the same stream** for TLS handshake and subsequent TLS operations
- TLS connection objects maintain internal state tied to the specific stream used
- Stream clones created after TLS state is established will not work correctly

### WouldBlock Handling in TLS
- `WouldBlock` from `conn.reader().read()` means "no decrypted data available"
- **Must attempt `read_tls()`** to read more encrypted data from the socket
- **Never ignore WouldBlock** without attempting to read more TLS data
- Proper flow: `read_tls()` → `process_new_packets()` → retry `conn.reader().read()`

### Common Mistakes to Avoid
1. ❌ Creating TlsReader with different stream than used for handshake
2. ❌ Early WouldBlock handlers that don't attempt TLS data reading
3. ❌ Assuming TLS handshake completion means data is immediately available
4. ❌ Complex borrowing patterns when accessing TLS connection and stream

## Testing Verification

### Working Behavior
```bash
curl -v https://example.com:8080/test
```

**Expected Logs:**
```
INFO  TLS handshake complete with X.X.X.X:XXXX
DEBUG Starting HTTP request parse  
DEBUG TLS fill_buf starting, waiting for data...
DEBUG TLS fill_buf got 123 bytes of data
INFO  📥 GET /test [listener-name] (TLS)
INFO  🔄 Forwarding to backend: backend.example.com:8080
```

### Failure Indicators (Fixed)
- ❌ `TLS fill_buf timeout` errors after successful handshake
- ❌ Missing "reading more TLS data" debug logs  
- ❌ Infinite retry loops with 1ms sleeps

## Related Files
- `src/main.rs`: `TlsReader` implementation and `handle_tls_connection_with_routing`
- `docs/TLS_READER_DEBUGGING.md`: Original TLS WouldBlock handling documentation

## Performance Notes
- Fixed stream usage eliminates unnecessary data copying between streams
- Proper WouldBlock handling reduces CPU usage by avoiding busy loops
- Debug logging can be disabled in production for optimal performance

---

**Date**: November 24, 2025  
**Issue**: TLS stream mismatch and incorrect WouldBlock handling  
**Resolution**: Consistent stream usage and proper TLS data flow implementation