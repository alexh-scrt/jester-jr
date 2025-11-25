//! WASM validator support

mod loader;
mod runtime;

pub use loader::WasmValidator;
pub use runtime::WasmRuntime;