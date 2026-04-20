use axum::{
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../../web/"]
pub struct WebAssets;

/// Returns true if `path` ends with a known static file extension.
/// Used to distinguish SPA client-side routes (no extension) from
/// missing static asset requests (has extension → 404).
fn has_file_extension(path: &str) -> bool {
    // Only the final path segment matters
    let last_segment = path.rsplit('/').next().unwrap_or(path);
    matches!(
        last_segment
            .rsplit('.')
            .next()
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some(
            "html"
                | "js"
                | "css"
                | "json"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "svg"
                | "ico"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
                | "map"
                | "txt"
                | "xml"
                | "webp"
        )
    )
}

pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match WebAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None if !has_file_extension(path) => {
            // SPA fallback: route has no known file extension, serve index.html
            match WebAssets::get("index.html") {
                Some(content) => (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    content.data,
                )
                    .into_response(),
                None => (StatusCode::NOT_FOUND, "index.html not found").into_response(),
            }
        }
        None => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
    }
}
