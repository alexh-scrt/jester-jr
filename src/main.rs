//! # Jester Jr. - A Lightweight Reverse Proxy
//!
//! Jester Jr. is a configurable HTTP reverse proxy built in Rust that provides
//! request and response filtering capabilities with bidirectional streaming support.
//!
//! ## Features
//! - HTTP/1.1 reverse proxy with bidirectional streaming
//! - Configurable request filtering (by method, path, headers)
//! - Configurable response filtering (by status code, size)
//! - TOML-based configuration
//! - Zero-copy header forwarding for efficient proxying
//!
//! ## Author
//! a13x.h.cc@gmail.com

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, Error as IoError, BufReader};
use std::time::Duration;
use std::thread;
use std::env;

mod config;
mod parsers;

use config::{Config, CompiledRequestRule, CompiledResponseRule};
use parsers::{HttpRequest, HttpResponse};

fn main() {
    // Get config file path from command line or use default
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "jester-jr.toml"
    };
    
    println!("🔧 Loading configuration from: {}", config_path);
    
    // Load and compile configuration
    let config = match Config::from_file(config_path) {
        Ok(cfg) => {
            println!("✅ Configuration loaded successfully");
            cfg
        }
        Err(e) => {
            eprintln!("❌ Failed to load config: {}", e);
            eprintln!("   Usage: {} [config_file.toml]", args.get(0).unwrap_or(&"jester-jr".to_string()));
            std::process::exit(1);
        }
    };
    
    // Compile filtering rules
    let request_rules = match config.compile_request_rules() {
        Ok(rules) => {
            println!("✅ Compiled {} request rules", rules.len());
            for rule in &rules {
                println!("   - {}: {:?}", rule.name, rule.action);
            }
            rules
        }
        Err(e) => {
            eprintln!("❌ Failed to compile request rules: {}", e);
            std::process::exit(1);
        }
    };
    
    let response_rules = config.compile_response_rules();
    println!("✅ Compiled {} response rules", response_rules.len());
    for rule in &response_rules {
        println!("   - {}: {:?}", rule.name, rule.action);
    }
    
    // Start the server with compiled rules
    if let Err(e) = run_server(config, request_rules, response_rules) {
        eprintln!("❌ Server error: {}", e);
        std::process::exit(1);
    }
}
/// Runs the main server loop, accepting and handling incoming connections.
///
/// This function binds to the configured listen address and enters an infinite loop
/// accepting incoming TCP connections. Each connection is handled synchronously with
/// full HTTP parsing and filtering.
///
/// # Arguments
/// * `config` - Server configuration including listen/backend addresses and timeouts
/// * `request_rules` - Compiled request filtering rules
/// * `response_rules` - Compiled response filtering rules
///
/// # Returns
/// * `Ok(())` - Never returns normally (infinite loop)
/// * `Err(IoError)` - If the TCP listener fails to bind
fn run_server(
    config: Config,
    request_rules: Vec<CompiledRequestRule>,
    response_rules: Vec<CompiledResponseRule>,
) -> Result<(), IoError> {
    let timeout = Duration::from_secs(config.proxy.timeout_seconds);
    
    let listener = TcpListener::bind(&config.proxy.listen_address)?;
    println!("\n🃏 Jester Jr is listening on http://{}", config.proxy.listen_address);
    println!("🎯 Forwarding requests to http://{}", config.proxy.backend_address);
    println!("⚡ Using BIDIRECTIONAL STREAMING with HTTP Parsing");
    println!("🔍 Request filtering: {} rule(s)", request_rules.len());
    println!("🔍 Response filtering: {} rule(s)", response_rules.len());
    println!();

    // Accept connections in a loop
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let backend = config.proxy.backend_address.clone();
                let req_rules = request_rules.clone();
                let resp_rules = response_rules.clone();
                
                if let Err(e) = handle_connection_with_parsing(
                    stream, 
                    &backend, 
                    timeout, 
                    timeout,
                    &req_rules,
                    &resp_rules,
                ) {
                    eprintln!("⚠️  Error handling connection: {}", e);
                }
            }
            Err(e) => {
                eprintln!("⚠️  Failed to accept connection: {}", e);
            }
        }
    }
    
    Ok(())
}

/// Handles a single client connection with full HTTP parsing and filtering.
///
/// This function:
/// 1. Parses the incoming HTTP request headers
/// 2. Evaluates request against filtering rules
/// 3. Forwards request to backend server
/// 4. Streams request body in a background thread (if present)
/// 5. Parses backend response headers
/// 6. Evaluates response against filtering rules
/// 7. Streams response body back to client
///
/// # Arguments
/// * `client_stream` - TCP stream connected to the client
/// * `backend_addr` - Address of the backend server to proxy to
/// * `read_timeout` - Timeout for read operations
/// * `write_timeout` - Timeout for write operations
/// * `request_rules` - Rules to evaluate incoming requests against
/// * `response_rules` - Rules to evaluate backend responses against
///
/// # Returns
/// * `Ok(())` - Connection handled successfully
/// * `Err(IoError)` - If any I/O operation fails
fn handle_connection_with_parsing(
    client_stream: TcpStream,
    backend_addr: &str,
    read_timeout: Duration,
    write_timeout: Duration,
    request_rules: &[CompiledRequestRule],
    response_rules: &[CompiledResponseRule],
) -> Result<(), IoError> {
    let peer_addr = client_stream.peer_addr()?;
    println!("\n✨ New connection from: {}", peer_addr);
    
    // Set timeouts
    client_stream.set_read_timeout(Some(read_timeout))?;
    client_stream.set_write_timeout(Some(write_timeout))?;
    
    // Create buffered reader for parsing headers efficiently
    let mut client_reader = BufReader::new(client_stream.try_clone()?);
    let mut client_writer = client_stream;
    
    // Parse the HTTP request headers
    let request = match HttpRequest::parse(&mut client_reader) {
        Ok(req) => {
            println!("📨 {} {} {} from {}", req.method, req.path, req.version, peer_addr);
            println!("   Headers: {} header(s)", req.headers.len());
            if let Some(cl) = req.content_length {
                println!("   Content-Length: {} bytes", cl);
            }
            req
        }
        Err(e) => {
            eprintln!("❌ Failed to parse request: {}", e);
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
            client_writer.write_all(response.as_bytes())?;
            return Ok(());
        }
    };
    
    // Check if request should be allowed (filtering logic)
    match request.should_allow(request_rules) {
        Ok(()) => {
            println!("✅ Request allowed");
        }
        Err(reason) => {
            println!("🚫 Request blocked: {}", reason);
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
                reason.len(),
                reason
            );
            client_writer.write_all(response.as_bytes())?;
            return Ok(());
        }
    }
    
    // Connect to the backend server
    println!("🔗 Connecting to backend at {}", backend_addr);
    let backend_stream = match TcpStream::connect(backend_addr) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("❌ Failed to connect to backend: {}", e);
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";
            client_writer.write_all(response.as_bytes())?;
            return Ok(());
        }
    };
    
    backend_stream.set_read_timeout(Some(read_timeout))?;
    backend_stream.set_write_timeout(Some(write_timeout))?;
    
    let mut backend_writer = backend_stream.try_clone()?;
    let mut backend_reader = BufReader::new(backend_stream);
    
    // Forward the request headers to backend
    println!("➡️  Forwarding request headers ({} bytes)", request.raw_headers.len());
    backend_writer.write_all(&request.raw_headers)?;
    backend_writer.flush()?;
    
    // Spawn thread to stream request body (if present)
    let request_body_handle = if request.has_body() {
        println!("➡️  Streaming request body...");
        Some(thread::spawn(move || {
            let mut total_bytes = 0u64;
            let mut buffer = [0u8; 8192];
            
            loop {
                match client_reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = backend_writer.write_all(&buffer[..n]) {
                            eprintln!("   ⚠️  Error forwarding request body: {}", e);
                            break;
                        }
                        total_bytes += n as u64;
                    }
                    Err(e) => {
                        eprintln!("   ⚠️  Error reading request body: {}", e);
                        break;
                    }
                }
            }
            
            let _ = backend_writer.flush();
            let _ = backend_writer.shutdown(std::net::Shutdown::Write);
            println!("   ➡️  Request body complete: {} bytes", total_bytes);
        }))
    } else {
        // No body, signal we're done writing
        let _ = backend_writer.shutdown(std::net::Shutdown::Write);
        None
    };
    
    // Parse the response headers from backend
    let response = match HttpResponse::parse(&mut backend_reader) {
        Ok(resp) => {
            println!("⬅️  {} {} {}", resp.version, resp.status_code, resp.status_text);
            println!("   Headers: {} header(s)", resp.headers.len());
            if let Some(cl) = resp.content_length {
                println!("   Content-Length: {} bytes", cl);
            }
            resp
        }
        Err(e) => {
            eprintln!("❌ Failed to parse response: {}", e);
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 23\r\n\r\nError reading response";
            client_writer.write_all(response.as_bytes())?;
            return Ok(());
        }
    };
    
    // Check if response should be allowed (filtering logic)
    match response.should_allow(response_rules) {
        Ok(()) => {
            println!("✅ Response allowed");
        }
        Err(reason) => {
            println!("🚫 Response blocked: {}", reason);
            let error_msg = format!("Response filtered: {}", reason);
            let error_response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{}",
                error_msg.len(),
                error_msg
            );
            client_writer.write_all(error_response.as_bytes())?;
            return Ok(());
        }
    }
    
    // Forward response headers to client
    println!("⬅️  Forwarding response headers ({} bytes)", response.raw_headers.len());
    client_writer.write_all(&response.raw_headers)?;
    client_writer.flush()?;
    
    // Stream response body to client
    if response.has_body() {
        println!("⬅️  Streaming response body...");
        let mut total_bytes = 0u64;
        let mut buffer = [0u8; 8192];
        
        loop {
            match backend_reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = client_writer.write_all(&buffer[..n]) {
                        eprintln!("   ⚠️  Error forwarding response body: {}", e);
                        break;
                    }
                    total_bytes += n as u64;
                }
                Err(e) => {
                    eprintln!("   ⚠️  Error reading response body: {}", e);
                    break;
                }
            }
        }
        
        client_writer.flush()?;
        println!("   ⬅️  Response body complete: {} bytes", total_bytes);
    }
    
    // Wait for request body thread if it exists
    if let Some(handle) = request_body_handle {
        let _ = handle.join();
    }
    
    println!("✅ Proxy complete for {}", peer_addr);
    
    Ok(())
}