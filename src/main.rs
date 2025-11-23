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
use rustls::ServerConnection;
use std::env;
use std::io::{BufReader, Error as IoError, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};
mod config;
mod parsers;
mod routing;
mod tls;

use config::{CompiledListener, CompiledRequestRule, CompiledResponseRule, Config};
use parsers::{HttpRequest, HttpResponse};

const APP_LOG_DIRECTIVE: &str = "jester-jr=info";

fn init_tracing(directives: Option<&str>) {
    // Build an EnvFilter to control levels.
    // Default level: info
    // You can override per-module, e.g.:
    //   RUST_LOG=tracing_example=debug,tracing_example::worker=trace
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(directives.unwrap_or(APP_LOG_DIRECTIVE)));

    // Build a formatting layer:
    // - with_target(true): show module/target
    // - with_level(true): show level
    // - with_line_number(true): show line number
    // - pretty(): human-friendly, colored output
    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_line_number(true)
        .with_thread_ids(false)
        .pretty();

    // Combine into a subscriber and set it as global.
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
}

fn main() {
    // Load configuration
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "jester-jr.toml"
    };

    init_tracing(None);

    info!("🔧 Loading configuration from: {}", config_path);

    let mut config = match Config::from_file(config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("❌ Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    // Migrate legacy config if needed
    config.migrate_from_legacy();

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("❌ Configuration validation failed: {}", e);
        std::process::exit(1);
    }

    // Compile all listeners
    let listeners = match config.compile_listeners() {
        Ok(listeners) => {
            info!("✅ Compiled {} listener(s)", listeners.len());
            for listener in &listeners {
                info!("   • {} → {}:{}", listener.name, listener.ip, listener.port);
                info!("     Routes: {}", listener.routes.len());
                if let Some(desc) = &listener.description {
                    info!("     Description: {}", desc);
                }
            }
            listeners
        }
        Err(e) => {
            error!("❌ Failed to compile listeners: {}", e);
            std::process::exit(1);
        }
    };

    // Start all listeners
    if let Err(e) = run_multi_listeners(listeners) {
        error!("❌ Server error: {}", e);
        std::process::exit(1);
    }
}

#[instrument(skip(listeners), level = "debug")]
fn run_multi_listeners(listeners: Vec<CompiledListener>) -> Result<(), std::io::Error> {
    if listeners.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No listeners configured",
        ));
    }

    let mut handles = vec![];

    for listener in listeners {
        debug!(listener = %listener.name, "Starting listener thread");
        let handle = thread::spawn(move || {
            if let Err(e) = run_single_listener(listener) {
                error!("❌ Listener error: {}", e);
            }
        });
        handles.push(handle);
    }

    // Wait for all listener threads
    for handle in handles {
        let _ = handle.join();
    }

    Ok(())
}

#[instrument(skip(listener))]
fn run_single_listener(listener: CompiledListener) -> Result<(), std::io::Error> {
    let listen_addr = format!("{}:{}", listener.ip, listener.port);
    let timeout = Duration::from_secs(listener.timeout_seconds);
    debug!(listener = %listener.name, %listen_addr, timeout_secs = listener.timeout_seconds, "Initializing listener");
    debug!(
        tls_enabled = listener.tls.as_ref().map(|t| t.enabled).unwrap_or(false),
        "TLS setting for listener"
    );

    // Load TLS config if enabled
    let tls_config = if let Some(tls_settings) = &listener.tls {
        if tls_settings.enabled {
            match tls::create_tls_config(&tls_settings.cert_file, &tls_settings.key_file) {
                Ok(config) => {
                    info!("🔒 TLS enabled for {}", listener.name);
                    Some(config)
                }
                Err(e) => {
                    error!("❌ Failed to initialize TLS for {}: {}", listener.name, e);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("TLS init failed: {}", e),
                    ));
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let tcp_listener = TcpListener::bind(&listen_addr)?;
    let protocol = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };
    debug!(%protocol, %listen_addr, "Listener bound");

    info!(
        "\n🃏 Listener '{}' active on {}://{}",
        listener.name, protocol, listen_addr
    );
    info!("   Routes: {}", listener.routes.len());
    info!("   Default action: {}", listener.default_action);
    if let Some(backend) = &listener.default_backend {
        info!("   Default backend: {}", backend);
    }

    // Wrap listener in Arc for sharing across threads
    let listener_arc = Arc::new(listener);

    for stream in tcp_listener.incoming() {
        match stream {
            Ok(stream) => {
                let listener_clone = Arc::clone(&listener_arc);
                let tls_cfg_clone = tls_config.clone();

                thread::spawn(move || {
                    if let Err(e) = handle_connection_with_routing(
                        stream,
                        listener_clone,
                        timeout,
                        timeout,
                        tls_cfg_clone,
                    ) {
                        warn!("⚠️  Error handling connection: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("⚠️  Failed to accept connection: {}", e);
            }
        }
    }

    Ok(())
}

#[instrument(skip(client_stream, listener, tls_config))]
fn handle_connection_with_routing(
    client_stream: TcpStream,
    listener: Arc<CompiledListener>,
    read_timeout: Duration,
    write_timeout: Duration,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), std::io::Error> {
    let peer_addr = client_stream.peer_addr()?;
    info!(
        "\n✨ New connection from: {} [{}]",
        peer_addr, listener.name
    );

    client_stream.set_read_timeout(Some(read_timeout))?;
    client_stream.set_write_timeout(Some(write_timeout))?;

    if let Some(tls_cfg) = tls_config {
        handle_tls_connection_with_routing(
            client_stream,
            listener,
            read_timeout,
            write_timeout,
            tls_cfg,
        )
    } else {
        handle_plain_connection_with_routing(client_stream, listener, read_timeout, write_timeout)
    }
}

#[instrument(skip(client_stream, listener))]
fn handle_plain_connection_with_routing(
    client_stream: TcpStream,
    listener: Arc<CompiledListener>,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), std::io::Error> {
    let peer_addr = client_stream.peer_addr()?;
    info!("✨ New connection from: {} [{}]", peer_addr, listener.name);

    // Set timeouts
    client_stream.set_read_timeout(Some(read_timeout))?;
    client_stream.set_write_timeout(Some(write_timeout))?;

    // Create buffered reader for parsing headers efficiently
    let mut client_reader = BufReader::new(client_stream.try_clone()?);
    let mut client_writer = client_stream;

    // Parse the HTTP request
    let request = match HttpRequest::parse(&mut client_reader) {
        Ok(req) => {
            info!("📥 {} {} [{}]", req.method, req.path, listener.name);
            req
        }
        Err(e) => {
            warn!("⚠️  Failed to parse request: {}", e);
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
            let _ = client_writer.write_all(response.as_bytes());
            return Ok(());
        }
    };

    // Match route using routing module
    let route_match = match routing::match_route(&listener, &request.path) {
        Some(m) => m,
        None => {
            // No route matched - check default action
            if let Some(backend) = routing::get_default_backend(&listener) {
                info!(
                    "🔄 No route matched, forwarding to default backend: {}",
                    backend
                );
                return forward_to_backend_with_path(
                    &request,
                    backend,
                    &request.path, // Use original path for default backend
                    client_writer,
                    &listener.response_rules,
                    &listener.response_rules,
                    read_timeout,
                    write_timeout,
                );
            } else {
                // Return 404
                info!("❌ No route found for {} [{}]", request.path, listener.name);
                let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
                client_writer.write_all(response.as_bytes())?;
                return Ok(());
            }
        }
    };

    let route_name = route_match.route.name.as_deref().unwrap_or("unnamed");
    info!(
        "🎯 Matched route '{}' → {} (path: {} → {})",
        route_name, route_match.route.backend, request.path, route_match.rewritten_path
    );

    // Apply listener-level request rules first
    if let Err(reason) = request.should_allow(&listener.request_rules) {
        warn!("🚫 Blocked by listener rule: {}", reason);
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            reason.len(),
            reason
        );
        client_writer.write_all(response.as_bytes())?;
        return Ok(());
    }

    // Apply route-level request rules
    if let Err(reason) = request.should_allow(&route_match.route.request_rules) {
        warn!("🚫 Blocked by route rule: {}", reason);
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            reason.len(),
            reason
        );
        client_writer.write_all(response.as_bytes())?;
        return Ok(());
    }

    // Forward to matched backend with rewritten path
    forward_to_backend_with_path(
        &request,
        &route_match.route.backend,
        &route_match.rewritten_path, // Use rewritten path
        client_writer,
        &listener.response_rules,          // Listener-level response rules
        &route_match.route.response_rules, // Route-level response rules
        read_timeout,
        write_timeout,
    )
}

#[instrument(skip(client_stream, listener, tls_config))]
fn handle_tls_connection_with_routing(
    client_stream: TcpStream,
    listener: Arc<CompiledListener>,
    read_timeout: Duration,
    write_timeout: Duration,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<(), std::io::Error> {
    let peer_addr = client_stream.peer_addr()?;
    info!(
        "✨ New TLS connection from: {} [{}]",
        peer_addr, listener.name
    );

    // Set timeouts
    client_stream.set_read_timeout(Some(read_timeout))?;
    client_stream.set_write_timeout(Some(write_timeout))?;

    // Create TLS server connection
    let mut tls_conn = ServerConnection::new(tls_config).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("TLS setup failed: {}", e),
        )
    })?;

    info!("🔒 Performing TLS handshake with {}...", peer_addr);

    // Perform TLS handshake
    let mut client_stream_clone = client_stream.try_clone()?;

    // Complete TLS handshake with timeout
    let handshake_start = std::time::Instant::now();
    let handshake_timeout = std::time::Duration::from_secs(10); // 10 second handshake timeout
    
    debug!("Starting TLS handshake loop, is_handshaking: {}", tls_conn.is_handshaking());
    while tls_conn.is_handshaking() {
        // Check handshake timeout
        if handshake_start.elapsed() > handshake_timeout {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TLS handshake timeout",
            ));
        }

        // Read TLS handshake data from client
        match tls_conn.read_tls(&mut client_stream_clone) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Client closed connection during handshake",
                ));
            }
            Ok(_) => {
                // Process the received handshake data
                if let Err(e) = tls_conn.process_new_packets() {
                    warn!("TLS process_new_packets error: {}", e);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("TLS handshake error: {}", e),
                    ));
                }

                // Send TLS handshake response back to client
                if let Err(e) = tls_conn.write_tls(&mut client_stream_clone) {
                    warn!("TLS write_tls error: {}", e);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to write TLS handshake response: {}", e),
                    ));
                }
                
                // Force flush the TCP stream to ensure handshake data is sent immediately
                if let Err(e) = client_stream_clone.flush() {
                    warn!("Failed to flush TLS handshake data: {}", e);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // This is normal for non-blocking I/O - continue trying with a brief sleep
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    debug!("TLS handshake loop completed, is_handshaking: {}", tls_conn.is_handshaking());
    info!("🔒 TLS handshake complete with {}", peer_addr);

    // Create a wrapper for reading decrypted data
    let mut tls_reader = TlsReader {
        conn: tls_conn,
        stream: client_stream,
        buffer: Vec::new(),
        buffer_pos: 0,
    };

    // Parse the HTTP request from decrypted stream
    let request = match HttpRequest::parse(&mut tls_reader) {
        Ok(req) => {
            info!("📥 {} {} [{}] (TLS)", req.method, req.path, listener.name);
            req
        }
        Err(e) => {
            warn!("⚠️  Failed to parse TLS request: {}", e);
            debug!("TLS parse failure for peer {}", peer_addr);
            let response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";

            // Send encrypted error response
            let mut client_writer = client_stream_clone;
            let mut conn = tls_reader.get_connection();
            let _ = conn.writer().write_all(response);
            let _ = conn.write_tls(&mut client_writer);
            return Ok(());
        }
    };

    // Match route using routing module (same logic as plain HTTP)
    let route_match = match routing::match_route(&listener, &request.path) {
        Some(m) => m,
        None => {
            // No route matched - check default action
            if let Some(backend) = routing::get_default_backend(&listener) {
                info!(
                    "🔄 No route matched, forwarding to default backend: {}",
                    backend
                );
                return forward_to_backend_with_path_tls(
                    &request,
                    backend,
                    &request.path,
                    tls_reader,
                    &listener.response_rules,
                    &listener.response_rules,
                    read_timeout,
                    write_timeout,
                );
            } else {
                // Return 404
                info!(
                    "❌ No route found for {} [{}] (TLS)",
                    request.path, listener.name
                );
                let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";

                let mut client_writer = client_stream_clone;
                let mut conn = tls_reader.get_connection();
                let _ = conn.writer().write_all(response);
                let _ = conn.write_tls(&mut client_writer);
                return Ok(());
            }
        }
    };

    let route_name = route_match.route.name.as_deref().unwrap_or("unnamed");
    info!(
        "🎯 Matched route '{}' → {} (path: {} → {}) (TLS)",
        route_name, route_match.route.backend, request.path, route_match.rewritten_path
    );

    // Apply listener-level request rules first
    if let Err(reason) = request.should_allow(&listener.request_rules) {
        warn!("🚫 Blocked by listener rule: {}", reason);
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            reason.len(),
            reason
        );

        let mut client_writer = client_stream_clone;
        let mut conn = tls_reader.get_connection();
        let _ = conn.writer().write_all(response.as_bytes());
        let _ = conn.write_tls(&mut client_writer);
        return Ok(());
    }

    // Apply route-level request rules
    if let Err(reason) = request.should_allow(&route_match.route.request_rules) {
        warn!("🚫 Blocked by route rule: {}", reason);
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            reason.len(),
            reason
        );

        let mut client_writer = client_stream_clone;
        let mut conn = tls_reader.get_connection();
        let _ = conn.writer().write_all(response.as_bytes());
        let _ = conn.write_tls(&mut client_writer);
        return Ok(());
    }

    // Forward to matched backend with rewritten path
    forward_to_backend_with_path_tls(
        &request,
        &route_match.route.backend,
        &route_match.rewritten_path,
        tls_reader,
        &listener.response_rules,
        &route_match.route.response_rules,
        read_timeout,
        write_timeout,
    )
}

/// Forward request to backend with custom path and merged response rules
#[instrument(skip(request, client_writer, response_rules_1, response_rules_2))]
fn forward_to_backend_with_path(
    request: &HttpRequest,
    backend_addr: &str,
    rewritten_path: &str,
    mut client_writer: TcpStream,
    response_rules_1: &[CompiledResponseRule],
    response_rules_2: &[CompiledResponseRule],
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), std::io::Error> {
    info!("🔗 Connecting to backend at {}", backend_addr);
    debug!(original_path = %request.path, rewritten_path = %rewritten_path, backend = %backend_addr, "Prepared backend forward");

    // Connect to backend
    let backend_stream = match TcpStream::connect(backend_addr) {
        Ok(stream) => stream,
        Err(e) => {
            error!("❌ Failed to connect to backend: {}", e);
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";
            client_writer.write_all(response.as_bytes())?;
            return Ok(());
        }
    };

    backend_stream.set_read_timeout(Some(read_timeout))?;
    backend_stream.set_write_timeout(Some(write_timeout))?;

    let mut backend_writer = backend_stream.try_clone()?;
    let mut backend_reader = BufReader::new(backend_stream);

    // Rebuild request headers with rewritten path
    let request_line = format!(
        "{} {} {}\r\n",
        request.method, rewritten_path, request.version
    );
    info!(
        "➡️  Forwarding request: {} {} → {}",
        request.method, request.path, rewritten_path
    );

    // Write request line
    backend_writer.write_all(request_line.as_bytes())?;

    // Write headers (skip the first line since we rebuilt it)
    let mut skip_first_line = true;
    for line in String::from_utf8_lossy(&request.raw_headers).lines() {
        if skip_first_line {
            skip_first_line = false;
            continue;
        }
        backend_writer.write_all(format!("{}\r\n", line).as_bytes())?;
    }

    // Write empty line to end headers
    backend_writer.write_all(b"\r\n")?;
    backend_writer.flush()?;

    // Handle request body if present (using existing logic)
    if request.has_body() {
        info!("➡️  Request has body, but streaming not implemented in Phase 4");
        // TODO: Implement body streaming in future versions
    }

    // Read backend response
    let response = match HttpResponse::parse(&mut backend_reader) {
        Ok(resp) => {
            info!(
                "📨 Backend response: {} {}",
                resp.status_code, resp.status_text
            );
            resp
        }
        Err(e) => {
            error!("❌ Failed to parse backend response: {}", e);
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";
            client_writer.write_all(response.as_bytes())?;
            return Ok(());
        }
    };

    // Evaluate merged response rules
    if let Err(reason) =
        evaluate_merged_response_rules(&response, response_rules_1, response_rules_2)
    {
        warn!("🚫 Response blocked: {}", reason);
        let error_response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            reason.len(),
            reason
        );
        client_writer.write_all(error_response.as_bytes())?;
        return Ok(());
    }

    // Forward response to client
    info!("📤 Forwarding response headers to client");
    client_writer.write_all(&response.raw_headers)?;
    client_writer.flush()?;

    // Stream response body if present (using existing logic)
    if response.has_body() {
        info!("📤 Streaming response body...");
        // TODO: Implement proper body streaming
    }

    Ok(())
}

/// Forward TLS request to backend with custom path  
#[instrument(skip(request, tls_reader, response_rules_1, response_rules_2))]
fn forward_to_backend_with_path_tls(
    request: &HttpRequest,
    backend_addr: &str,
    rewritten_path: &str,
    tls_reader: TlsReader,
    response_rules_1: &[CompiledResponseRule],
    response_rules_2: &[CompiledResponseRule],
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), std::io::Error> {
    info!("🔗 Connecting to backend at {} (TLS client)", backend_addr);
    debug!(original_path = %request.path, rewritten_path = %rewritten_path, backend = %backend_addr, "Prepared backend forward (TLS client)");

    // Extract TLS connection and stream once
    let TlsReader {
        conn: mut tls_conn,
        stream: mut client_stream,
        ..
    } = tls_reader;

    // Connect to backend (plain HTTP - TLS termination)
    let backend_stream = match TcpStream::connect(backend_addr) {
        Ok(stream) => stream,
        Err(e) => {
            error!("❌ Failed to connect to backend: {}", e);
            let response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";

            // Send encrypted error response
            let _ = tls_conn.writer().write_all(response);
            let _ = tls_conn.write_tls(&mut client_stream);
            return Ok(());
        }
    };

    backend_stream.set_read_timeout(Some(read_timeout))?;
    backend_stream.set_write_timeout(Some(write_timeout))?;

    let mut backend_writer = backend_stream.try_clone()?;
    let mut backend_reader = BufReader::new(backend_stream);

    // Rebuild request headers with rewritten path
    let request_line = format!(
        "{} {} {}\r\n",
        request.method, rewritten_path, request.version
    );
    info!(
        "➡️  Forwarding TLS request: {} {} → {}",
        request.method, request.path, rewritten_path
    );

    // Write request line
    backend_writer.write_all(request_line.as_bytes())?;

    // Write headers (skip the first line since we rebuilt it)
    let mut skip_first_line = true;
    for line in String::from_utf8_lossy(&request.raw_headers).lines() {
        if skip_first_line {
            skip_first_line = false;
            continue;
        }
        backend_writer.write_all(format!("{}\r\n", line).as_bytes())?;
    }

    // Write empty line to end headers
    backend_writer.write_all(b"\r\n")?;
    backend_writer.flush()?;

    // Read backend response
    let response = match HttpResponse::parse(&mut backend_reader) {
        Ok(resp) => {
            info!(
                "📨 Backend response: {} {} (TLS client)",
                resp.status_code, resp.status_text
            );
            resp
        }
        Err(e) => {
            error!("❌ Failed to parse backend response: {}", e);
            let response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";

            let _ = tls_conn.writer().write_all(response);
            let _ = tls_conn.write_tls(&mut client_stream);
            return Ok(());
        }
    };

    // Evaluate merged response rules
    if let Err(reason) =
        evaluate_merged_response_rules(&response, response_rules_1, response_rules_2)
    {
        warn!("🚫 Response blocked: {}", reason);
        let error_response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            reason.len(),
            reason
        );

        let _ = tls_conn.writer().write_all(error_response.as_bytes());
        let _ = tls_conn.write_tls(&mut client_stream);
        return Ok(());
    }

    // Send encrypted response to client
    info!("📤 Forwarding response headers to TLS client");

    let _ = tls_conn.writer().write_all(&response.raw_headers);
    let _ = tls_conn.write_tls(&mut client_stream);

    Ok(())
}

/// Evaluate merged response rules (listener + route level)
fn evaluate_merged_response_rules(
    response: &HttpResponse,
    rules_1: &[CompiledResponseRule],
    rules_2: &[CompiledResponseRule],
) -> Result<(), String> {
    // First evaluate rules_1 (usually listener-level rules)
    if let Err(reason) = response.should_allow(rules_1) {
        return Err(reason);
    }

    // Then evaluate rules_2 (usually route-level rules)
    if let Err(reason) = response.should_allow(rules_2) {
        return Err(reason);
    }

    Ok(())
}

/// Helper to add take_connection and take_stream methods to TlsReader
impl TlsReader {
    fn get_connection(&mut self) -> &mut ServerConnection {
        &mut self.conn
    }

    fn get_stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    fn take_connection(self) -> ServerConnection {
        self.conn
    }

    fn take_stream(self) -> TcpStream {
        self.stream
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
/// * `tls_config` - Optional TLS configuration for secure connections
///
/// # Returns
/// * `Ok(())` - Never returns normally (infinite loop)
/// * `Err(IoError)` - If the TCP listener fails to bind
#[instrument(skip(config, request_rules, response_rules, tls_config))]
fn run_server(
    config: Config,
    request_rules: Vec<CompiledRequestRule>,
    response_rules: Vec<CompiledResponseRule>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), IoError> {
    let timeout = Duration::from_secs(config.proxy.as_ref().unwrap().timeout_seconds);

    let listener = TcpListener::bind(&config.proxy.as_ref().unwrap().listen_address)?;
    let protocol = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };
    info!(
        "\n🃏 Jester Jr is listening on {}://{}",
        protocol,
        config.proxy.as_ref().unwrap().listen_address
    );

    if tls_config.is_some() {
        info!("🔒 TLS/SSL: ENABLED");
    } else {
        info!("🔓 TLS/SSL: DISABLED");
    }
    info!(
        "🎯 Forwarding requests to http://{}",
        config.proxy.as_ref().unwrap().backend_address
    );
    info!("⚡ Using BIDIRECTIONAL STREAMING with HTTP Parsing");
    info!("🔍 Request filtering: {} rule(s)", request_rules.len());
    info!("🔍 Response filtering: {} rule(s)", response_rules.len());
    info!("");

    // Accept connections in a loop
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let backend = config.proxy.as_ref().unwrap().backend_address.clone();
                let req_rules = request_rules.clone();
                let resp_rules = response_rules.clone();
                let tls_cfg = tls_config.clone(); // ADD THIS

                thread::spawn(move || {
                    if let Err(e) = handle_connection(
                        stream,
                        &backend,
                        timeout,
                        timeout,
                        &req_rules,
                        &resp_rules,
                        tls_cfg, // TLS CONFIG
                    ) {
                        warn!("⚠️  Error handling connection: {}", e);
                    }
                });
            }

            Err(e) => {
                warn!("⚠️  Failed to accept connection: {}", e);
            }
        }
    }

    Ok(())
}

#[instrument(skip(client_stream, request_rules, response_rules, tls_config))]
fn handle_connection(
    client_stream: TcpStream,
    backend_addr: &str,
    read_timeout: Duration,
    write_timeout: Duration,
    request_rules: &[CompiledRequestRule],
    response_rules: &[CompiledResponseRule],
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), IoError> {
    let peer_addr = client_stream.peer_addr()?;
    info!("\n✨ New connection from: {}", peer_addr);
    debug!(%backend_addr, read_timeout = ?read_timeout, write_timeout = ?write_timeout, "Handling plain connection (legacy path)");
    debug!(%backend_addr, read_timeout = ?read_timeout, write_timeout = ?write_timeout, "Handling connection (legacy path)");

    client_stream.set_read_timeout(Some(read_timeout))?;
    client_stream.set_write_timeout(Some(write_timeout))?;

    if let Some(tls_cfg) = tls_config {
        info!("🔒 Performing TLS handshake...");
        handle_tls_connection(
            client_stream,
            backend_addr,
            read_timeout,
            write_timeout,
            request_rules,
            response_rules,
            tls_cfg,
        )
    } else {
        handle_plain_connection(
            client_stream,
            backend_addr,
            read_timeout,
            write_timeout,
            request_rules,
            response_rules,
        )
    }
}

/// Handle a TLS-encrypted connection
///
/// This function:
/// 1. Performs TLS handshake
/// 2. Decrypts the HTTP request
/// 3. Applies request filtering rules
/// 4. Forwards request to backend (plain HTTP)
/// 5. Encrypts and returns the response
///
/// Key insight: We keep ServerConnection in one place and manually
/// handle encryption/decryption at the right points.
#[instrument(skip(client_stream, request_rules, response_rules, tls_config))]
fn handle_tls_connection(
    mut client_stream: TcpStream,
    backend_addr: &str,
    read_timeout: Duration,
    write_timeout: Duration,
    request_rules: &[CompiledRequestRule],
    response_rules: &[CompiledResponseRule],
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<(), std::io::Error> {
    // Get peer address for logging
    let peer_addr = client_stream.peer_addr()?;

    // Create TLS connection
    let mut tls_conn = ServerConnection::new(tls_config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("TLS error: {}", e)))?;

    // ═══════════════════════════════════════════════════════════
    // PHASE 1: TLS HANDSHAKE
    // ═══════════════════════════════════════════════════════════
    info!("🔒 Performing TLS handshake with {}...", peer_addr);

    loop {
        // Read encrypted handshake data from client
        if tls_conn.wants_read() {
            match tls_conn.read_tls(&mut client_stream) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Connection closed during TLS handshake",
                    ));
                }
                Ok(_) => {
                    // Process the handshake messages
                    if let Err(e) = tls_conn.process_new_packets() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("TLS handshake error: {}", e),
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Would block - continue to write phase
                }
                Err(e) => return Err(e),
            }
        }

        // Write encrypted handshake data to client
        if tls_conn.wants_write() {
            tls_conn.write_tls(&mut client_stream)?;
        }

        // Check if handshake is complete
        if !tls_conn.is_handshaking() {
            info!("🔒 TLS handshake complete with {}", peer_addr);
            break;
        }
    }

    // ═══════════════════════════════════════════════════════════
    // PHASE 2: READ AND DECRYPT HTTP REQUEST
    // ═══════════════════════════════════════════════════════════

    // Helper function to read decrypted data
    let mut read_decrypted = |buf: &mut Vec<u8>| -> std::io::Result<usize> {
        // Try to read from existing decrypted buffer
        let initial_len = buf.len();
        buf.resize(initial_len + 8192, 0);

        match tls_conn.reader().read(&mut buf[initial_len..]) {
            Ok(0) => {
                // No data available, read more encrypted data
                buf.resize(initial_len, 0);

                match tls_conn.read_tls(&mut client_stream) {
                    Ok(0) => Ok(0), // Connection closed
                    Ok(_) => {
                        // Decrypt the data
                        tls_conn.process_new_packets().map_err(|e| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("TLS error: {}", e),
                            )
                        })?;

                        // Try reading again
                        match tls_conn.reader().read(&mut buf[initial_len..]) {
                            Ok(n) => {
                                buf.resize(initial_len + n, 0);
                                Ok(n)
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Ok(n) => {
                buf.resize(initial_len + n, 0);
                Ok(n)
            }
            Err(e) => {
                buf.resize(initial_len, 0);
                Err(e)
            }
        }
    };

    // Read and parse HTTP request headers
    let mut request_buffer = Vec::new();
    loop {
        let bytes_read = read_decrypted(&mut request_buffer)?;
        if bytes_read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed while reading request",
            ));
        }

        // Check if we have complete headers (ends with \r\n\r\n or \n\n)
        if request_buffer.windows(4).any(|w| w == b"\r\n\r\n")
            || request_buffer.windows(2).any(|w| w == b"\n\n")
        {
            break;
        }
    }

    // Parse the request
    let request = {
        let mut cursor = std::io::Cursor::new(&request_buffer);
        let mut reader = BufReader::new(&mut cursor);

        match HttpRequest::parse(&mut reader) {
            Ok(req) => {
                info!(
                    "📨 {} {} {} from {} (decrypted)",
                    req.method, req.path, req.version, peer_addr
                );
                debug!("   Headers: {} header(s)", req.headers.len());
                if let Some(cl) = req.content_length {
                    debug!("   Content-Length: {} bytes", cl);
                }
                req
            }
            Err(e) => {
                warn!("❌ Failed to parse request: {}", e);

                // Send encrypted error response
                let response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
                tls_conn.writer().write_all(response)?;
                tls_conn.write_tls(&mut client_stream)?;

                return Ok(());
            }
        }
    };

    // ═══════════════════════════════════════════════════════════
    // PHASE 3: REQUEST FILTERING
    // ═══════════════════════════════════════════════════════════
    match request.should_allow(request_rules) {
        Ok(()) => {
            info!("✅ Request allowed");
        }
        Err(reason) => {
            warn!("🚫 Request blocked: {}", reason);

            // Send encrypted error response
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
                reason.len(),
                reason
            );
            tls_conn.writer().write_all(response.as_bytes())?;
            tls_conn.write_tls(&mut client_stream)?;

            return Ok(());
        }
    }

    // ═══════════════════════════════════════════════════════════
    // PHASE 4: CONNECT TO BACKEND (Plain HTTP)
    // ═══════════════════════════════════════════════════════════
    info!("🔗 Connecting to backend at {}", backend_addr);
    let backend_stream = match TcpStream::connect(backend_addr) {
        Ok(stream) => stream,
        Err(e) => {
            error!("❌ Failed to connect to backend: {}", e);

            // Send encrypted error response
            let response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway";
            tls_conn.writer().write_all(response)?;
            tls_conn.write_tls(&mut client_stream)?;

            return Ok(());
        }
    };

    backend_stream.set_read_timeout(Some(read_timeout))?;
    backend_stream.set_write_timeout(Some(write_timeout))?;

    let mut backend_writer = backend_stream.try_clone()?;
    let mut backend_reader = BufReader::new(backend_stream);

    // ═══════════════════════════════════════════════════════════
    // PHASE 5: FORWARD REQUEST TO BACKEND (Plain HTTP)
    // ═══════════════════════════════════════════════════════════
    info!(
        "➡️  Forwarding request headers ({} bytes)",
        request.raw_headers.len()
    );
    backend_writer.write_all(&request.raw_headers)?;
    backend_writer.flush()?;

    // Handle request body if present
    if request.has_body() {
        info!("➡️  Streaming request body...");

        // We need to continue reading from the TLS connection
        // This is complex because we can't move tls_conn into the thread
        // For now, we'll handle this synchronously

        let mut total_bytes = 0u64;
        let content_length = request.content_length.unwrap_or(0);
        let mut remaining = content_length;

        while remaining > 0 {
            // Read decrypted data
            let to_read = std::cmp::min(remaining, 8192);
            let mut buffer = vec![0u8; to_read];

            // First check if we have buffered data in TLS reader
            match tls_conn.reader().read(&mut buffer) {
                Ok(0) => {
                    // Need to read more encrypted data
                    tls_conn.read_tls(&mut client_stream)?;
                    tls_conn.process_new_packets().map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("TLS error: {}", e),
                        )
                    })?;

                    // Try again
                    let n = tls_conn.reader().read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    backend_writer.write_all(&buffer[..n])?;
                    total_bytes += n as u64;
                    remaining -= n;
                }
                Ok(n) => {
                    backend_writer.write_all(&buffer[..n])?;
                    total_bytes += n as u64;
                    remaining -= n;
                }
                Err(e) => {
                    warn!("   ⚠️  Error reading request body: {}", e);
                    break;
                }
            }
        }

        backend_writer.flush()?;
        let _ = backend_writer.shutdown(std::net::Shutdown::Write);
        info!("   ➡️  Request body complete: {} bytes", total_bytes);

        // None // No thread needed
    } else {
        // No body, signal we're done writing
        let _ = backend_writer.shutdown(std::net::Shutdown::Write);
        // None
    };

    // ═══════════════════════════════════════════════════════════
    // PHASE 6: READ RESPONSE FROM BACKEND (Plain HTTP)
    // ═══════════════════════════════════════════════════════════
    let response = match HttpResponse::parse(&mut backend_reader) {
        Ok(resp) => {
            info!(
                "⬅️  {} {} {}",
                resp.version, resp.status_code, resp.status_text
            );
            debug!("   Headers: {} header(s)", resp.headers.len());
            if let Some(cl) = resp.content_length {
                debug!("   Content-Length: {} bytes", cl);
            }
            resp
        }
        Err(e) => {
            error!("❌ Failed to parse response: {}", e);

            // Send encrypted error response
            let response =
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 23\r\n\r\nError reading response";
            tls_conn.writer().write_all(response)?;
            tls_conn.write_tls(&mut client_stream)?;

            return Ok(());
        }
    };

    // ═══════════════════════════════════════════════════════════
    // PHASE 7: RESPONSE FILTERING
    // ═══════════════════════════════════════════════════════════
    match response.should_allow(response_rules) {
        Ok(()) => {
            info!("✅ Response allowed");
        }
        Err(reason) => {
            warn!("🚫 Response blocked: {}", reason);

            // Send encrypted error response
            let error_msg = format!("Response filtered: {}", reason);
            let error_response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{}",
                error_msg.len(),
                error_msg
            );
            tls_conn.writer().write_all(error_response.as_bytes())?;
            tls_conn.write_tls(&mut client_stream)?;

            return Ok(());
        }
    }

    // ═══════════════════════════════════════════════════════════
    // PHASE 8: FORWARD RESPONSE TO CLIENT (Encrypted)
    // ═══════════════════════════════════════════════════════════
    info!(
        "⬅️  Forwarding response headers ({} bytes)",
        response.raw_headers.len()
    );

    // Write headers through TLS (encrypts automatically)
    tls_conn.writer().write_all(&response.raw_headers)?;
    tls_conn.write_tls(&mut client_stream)?;

    // Stream response body (encrypted)
    if response.has_body() {
        info!("⬅️  Streaming response body...");
        let mut total_bytes = 0u64;
        let mut buffer = [0u8; 8192];

        loop {
            match backend_reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    // Write plaintext to TLS connection (encrypts)
                    if let Err(e) = tls_conn.writer().write_all(&buffer[..n]) {
                        warn!("   ⚠️  Error writing response body: {}", e);
                        break;
                    }

                    // Send encrypted data to client
                    if let Err(e) = tls_conn.write_tls(&mut client_stream) {
                        warn!("   ⚠️  Error sending encrypted data: {}", e);
                        break;
                    }

                    total_bytes += n as u64;
                }
                Err(e) => {
                    warn!("   ⚠️  Error reading response body: {}", e);
                    break;
                }
            }
        }

        // Flush any remaining data
        tls_conn.writer().flush()?;
        tls_conn.write_tls(&mut client_stream)?;
        client_stream.flush()?;

        info!("   ⬅️  Response body complete: {} bytes", total_bytes);
    }

    info!("✅ Proxy complete for {}", peer_addr);

    Ok(())
}

/// Helper struct for reading decrypted TLS data
/// 
/// CRITICAL: This reader handles the TLS decryption flow:
/// 1. read_tls() - Reads encrypted bytes from TCP socket
/// 2. process_new_packets() - Decrypts bytes into internal buffer
/// 3. conn.reader().read() - Reads decrypted data from internal buffer
/// 
/// IMPORTANT: Never return WouldBlock without attempting read_tls() first!
/// See docs/TLS_READER_DEBUGGING.md for detailed implementation notes.
struct TlsReader {
    conn: ServerConnection,
    stream: TcpStream,
    buffer: Vec<u8>,
    buffer_pos: usize,
}

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If we have buffered data, use that first
        if self.buffer_pos < self.buffer.len() {
            let available = self.buffer.len() - self.buffer_pos;
            let to_copy = std::cmp::min(buf.len(), available);
            buf[..to_copy]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
            self.buffer_pos += to_copy;
            return Ok(to_copy);
        }

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5); // 5 second timeout
        
        debug!("TLS read() starting, waiting for data...");
        loop {
            // Check timeout
            if start.elapsed() > timeout {
                debug!("TLS read() timeout after {:?}", start.elapsed());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut, 
                    "TLS read timeout - no data received"
                ));
            }

            // Try to read decrypted data directly
            match self.conn.reader().read(buf) {
                Ok(n) if n > 0 => {
                    debug!("TLS read() got {} bytes of data", n);
                    return Ok(n);
                }
                Ok(_) => {
                    // No decrypted data available, need to read more TLS data
                    match self.conn.read_tls(&mut self.stream) {
                        Ok(0) => {
                            debug!("TLS read() connection closed");
                            return Ok(0);
                        }
                        Ok(_) => {
                            // Process the new TLS data
                            self.conn.process_new_packets().map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            // Continue loop to try reading decrypted data again
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // This is normal for non-blocking I/O - wait briefly and continue
                            debug!("TLS read() WouldBlock, retrying... (elapsed: {:?})", start.elapsed());
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Handle WouldBlock at the reader level too
                    debug!("TLS read() direct WouldBlock, retrying... (elapsed: {:?})", start.elapsed());
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl std::io::BufRead for TlsReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        // If we already have data in the buffer, return it
        if self.buffer_pos < self.buffer.len() {
            return Ok(&self.buffer[self.buffer_pos..]);
        }

        // Reset buffer for new data
        self.buffer.clear();
        self.buffer_pos = 0;

        // Read more data from TLS connection with timeout
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5); // 5 second timeout
        
        debug!("TLS fill_buf starting, waiting for data...");
        loop {
            // Check timeout
            if start.elapsed() > timeout {
                debug!("TLS fill_buf timeout after {:?}", start.elapsed());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut, 
                    "TLS fill_buf timeout - no data received"
                ));
            }

            let mut temp_buf = [0u8; 1024];
            match self.conn.reader().read(&mut temp_buf) {
                Ok(n) if n > 0 => {
                    debug!("TLS fill_buf got {} bytes of data", n);
                    self.buffer.extend_from_slice(&temp_buf[..n]);
                    return Ok(&self.buffer[..]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Ok(_) => {
                    // Need more TLS data
                    match self.conn.read_tls(&mut self.stream) {
                        Ok(0) => {
                            // Connection closed
                            return Ok(&[]);
                        }
                        Ok(_) => {
                            self.conn.process_new_packets().map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            // Continue loop to try reading again
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // This is normal for non-blocking I/O - wait briefly and continue
                            debug!("TLS fill_buf WouldBlock, retrying... (elapsed: {:?})", start.elapsed());
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // CRITICAL: WouldBlock from conn.reader() means no decrypted data available,
                    // but encrypted data may be waiting in TCP socket. Must attempt read_tls()!
                    // See docs/TLS_READER_DEBUGGING.md for why this is essential.
                    debug!("TLS fill_buf conn.reader() WouldBlock, reading more TLS data... (elapsed: {:?})", start.elapsed());
                    match self.conn.read_tls(&mut self.stream) {
                        Ok(0) => {
                            // Connection closed
                            return Ok(&[]);
                        }
                        Ok(_) => {
                            self.conn.process_new_packets().map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            // Continue loop to try reading again
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // This is normal for non-blocking I/O - wait briefly and continue
                            debug!("TLS fill_buf read_tls WouldBlock, retrying... (elapsed: {:?})", start.elapsed());
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn consume(&mut self, amt: usize) {
        self.buffer_pos += amt;
        if self.buffer_pos >= self.buffer.len() {
            self.buffer.clear();
            self.buffer_pos = 0;
        }
    }
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
#[instrument(skip(client_stream, request_rules, response_rules))]
fn handle_plain_connection(
    client_stream: TcpStream,
    backend_addr: &str,
    read_timeout: Duration,
    write_timeout: Duration,
    request_rules: &[CompiledRequestRule],
    response_rules: &[CompiledResponseRule],
) -> Result<(), IoError> {
    let peer_addr = client_stream.peer_addr()?;
    info!("\n✨ New connection from: {}", peer_addr);

    // Set timeouts
    client_stream.set_read_timeout(Some(read_timeout))?;
    client_stream.set_write_timeout(Some(write_timeout))?;

    // Create buffered reader for parsing headers efficiently
    let mut client_reader = BufReader::new(client_stream.try_clone()?);
    let mut client_writer = client_stream;

    // Parse the HTTP request headers
    let request = match HttpRequest::parse(&mut client_reader) {
        Ok(req) => {
            info!(
                "📨 {} {} {} from {}",
                req.method, req.path, req.version, peer_addr
            );
            debug!("   Headers: {} header(s)", req.headers.len());
            if let Some(cl) = req.content_length {
                debug!("   Content-Length: {} bytes", cl);
            }
            req
        }
        Err(e) => {
            warn!("❌ Failed to parse request: {}", e);
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
            client_writer.write_all(response.as_bytes())?;
            return Ok(());
        }
    };

    // Check if request should be allowed (filtering logic)
    match request.should_allow(request_rules) {
        Ok(()) => {
            info!("✅ Request allowed");
        }
        Err(reason) => {
            warn!("🚫 Request blocked: {}", reason);
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
    info!("🔗 Connecting to backend at {}", backend_addr);
    let backend_stream = match TcpStream::connect(backend_addr) {
        Ok(stream) => stream,
        Err(e) => {
            error!("❌ Failed to connect to backend: {}", e);
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
    info!(
        "➡️  Forwarding request headers ({} bytes)",
        request.raw_headers.len()
    );
    backend_writer.write_all(&request.raw_headers)?;
    backend_writer.flush()?;

    // Spawn thread to stream request body (if present)
    let request_body_handle = if request.has_body() {
        info!("➡️  Streaming request body...");
        Some(thread::spawn(move || {
            let mut total_bytes = 0u64;
            let mut buffer = [0u8; 8192];

            loop {
                match client_reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = backend_writer.write_all(&buffer[..n]) {
                            warn!("   ⚠️  Error forwarding request body: {}", e);
                            break;
                        }
                        total_bytes += n as u64;
                    }
                    Err(e) => {
                        warn!("   ⚠️  Error reading request body: {}", e);
                        break;
                    }
                }
            }

            let _ = backend_writer.flush();
            let _ = backend_writer.shutdown(std::net::Shutdown::Write);
            info!("   ➡️  Request body complete: {} bytes", total_bytes);
        }))
    } else {
        // No body, signal we're done writing
        let _ = backend_writer.shutdown(std::net::Shutdown::Write);
        None
    };

    // Parse the response headers from backend
    let response = match HttpResponse::parse(&mut backend_reader) {
        Ok(resp) => {
            info!(
                "⬅️  {} {} {}",
                resp.version, resp.status_code, resp.status_text
            );
            debug!("   Headers: {} header(s)", resp.headers.len());
            if let Some(cl) = resp.content_length {
                debug!("   Content-Length: {} bytes", cl);
            }
            resp
        }
        Err(e) => {
            error!("❌ Failed to parse response: {}", e);
            let response =
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 23\r\n\r\nError reading response";
            client_writer.write_all(response.as_bytes())?;
            return Ok(());
        }
    };

    // Check if response should be allowed (filtering logic)
    match response.should_allow(response_rules) {
        Ok(()) => {
            info!("✅ Response allowed");
        }
        Err(reason) => {
            warn!("🚫 Response blocked: {}", reason);
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
    info!(
        "⬅️  Forwarding response headers ({} bytes)",
        response.raw_headers.len()
    );
    client_writer.write_all(&response.raw_headers)?;
    client_writer.flush()?;

    // Stream response body to client
    if response.has_body() {
        info!("⬅️  Streaming response body...");
        let mut total_bytes = 0u64;
        let mut buffer = [0u8; 8192];

        loop {
            match backend_reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = client_writer.write_all(&buffer[..n]) {
                        warn!("   ⚠️  Error forwarding response body: {}", e);
                        break;
                    }
                    total_bytes += n as u64;
                }
                Err(e) => {
                    warn!("   ⚠️  Error reading response body: {}", e);
                    break;
                }
            }
        }

        client_writer.flush()?;
        info!("   ⬅️  Response body complete: {} bytes", total_bytes);
    }

    // Wait for request body thread if it exists
    if let Some(handle) = request_body_handle {
        let _ = handle.join();
    }

    info!("✅ Proxy complete for {}", peer_addr);

    Ok(())
}
