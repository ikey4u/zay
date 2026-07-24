//! Build-time manifest for `webui/dist` (see `build.rs`).

#[derive(Clone, Copy)]
pub struct EmbeddedFile {
    pub path: &'static str,
    pub content_type: &'static str,
    pub body: &'static [u8],
}

include!(env!("ZAY_WEBUI_EMBED_RS"));

/// Normalize request path and look up an embedded file.
pub fn lookup(request_path: &str) -> Option<&'static EmbeddedFile> {
    if !EMBEDDED_UI {
        return None;
    }
    let path = request_path.split('?').next().unwrap_or(request_path);
    let path = if path.is_empty() || path == "/" {
        "/index.html"
    } else {
        path
    };
    FILES.iter().find(|f| f.path == path)
}
