//! HTTP parsing module for Jester Jr.
//!
//! This module provides efficient HTTP/1.1 request and response parsers that
//! read only the headers, leaving the body in the stream for zero-copy streaming.
//! This design enables efficient proxying with minimal memory overhead.
//!
//! ## Author
//! a13x.h.cc@gmail.com

mod request;
mod response;

pub use request::HttpRequest;
pub use response::HttpResponse;
