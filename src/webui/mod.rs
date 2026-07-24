//! Embedded WebUI static assets (`webui/dist` at build time).

pub mod embed;

pub use embed::{EMBEDDED_UI, lookup};
