//! HTTP/1.1 CONNECT outbound primitives.

use std::io;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    adapter::{DialFuture, Dialer},
    common::network::SocksAddr,
    option::User,
};

pub struct HttpConnectOutbound<D> {
    upstream: D,
    server: SocksAddr,
    username: String,
    password: String,
    path: String,
    headers: Map<String, Value>,
}

impl<D> HttpConnectOutbound<D> {
    pub fn new(
        upstream: D,
        server: SocksAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        path: impl Into<String>,
        headers: Map<String, Value>,
    ) -> Self {
        Self {
            upstream,
            server,
            username: username.into(),
            password: password.into(),
            path: path.into(),
            headers,
        }
    }
}

impl<D: Dialer> Dialer for HttpConnectOutbound<D> {
    fn dial_tcp<'a>(&'a self, destination: &'a SocksAddr) -> DialFuture<'a> {
        Box::pin(async move {
            let mut stream = self.upstream.dial_tcp(&self.server).await?;
            client_handshake(
                &mut stream,
                destination,
                (!self.username.is_empty()).then_some((
                    self.username.as_str(),
                    self.password.as_str(),
                )),
                &self.path,
                &self.headers,
            )
            .await?;
            Ok(stream)
        })
    }
}

pub async fn client_handshake<S>(
    stream: &mut S,
    destination: &SocksAddr,
    credentials: Option<(&str, &str)>,
    path: &str,
    headers: &Map<String, Value>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let authority = destination.to_string();
    let request_target = if path.is_empty() { &authority } else { path };
    let mut request =
        format!("CONNECT {request_target} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((username, password)) = credentials {
        let token = STANDARD.encode(format!("{username}:{password}"));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&token);
        request.push_str("\r\n");
    }
    for (name, value) in headers {
        validate_header_name(name)?;
        match value {
            Value::String(value) => append_header(&mut request, name, value)?,
            Value::Array(values) => {
                for value in values {
                    let value = value.as_str().ok_or_else(|| {
                        invalid_input(format!(
                            "HTTP header {name:?} contains a non-string value"
                        ))
                    })?;
                    append_header(&mut request, name, value)?;
                }
            }
            _ => {
                return Err(invalid_input(format!(
                    "HTTP header {name:?} is not a string or string array"
                )));
            }
        }
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_header(stream).await?;
    let status_line = response
        .split("\r\n")
        .next()
        .ok_or_else(|| invalid_data("empty HTTP CONNECT response"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| invalid_data("invalid HTTP CONNECT status line"))?;
    if !version.starts_with("HTTP/") {
        return Err(invalid_data("invalid HTTP CONNECT version"));
    }
    if !(200..300).contains(&status) {
        return Err(io::Error::new(
            if status == 407 {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::ConnectionRefused
            },
            format!("HTTP CONNECT failed with status {status}"),
        ));
    }
    Ok(())
}

pub async fn server_handshake<S>(
    stream: &mut S,
    users: &[User],
) -> io::Result<(SocksAddr, Option<String>)>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let request = read_header(stream).await?;
    let mut lines = request.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid_data("empty HTTP proxy request"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let target = request_parts.next().unwrap_or_default();
    let version = request_parts.next().unwrap_or_default();
    if request_parts.next().is_some() || !version.starts_with("HTTP/1.") {
        write_server_response(stream, 400, "Bad Request", &[]).await?;
        return Err(invalid_data("invalid HTTP proxy request line"));
    }
    if method != "CONNECT" {
        write_server_response(stream, 405, "Method Not Allowed", &[]).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported HTTP proxy method: {method}"),
        ));
    }
    let authorization = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("Proxy-Authorization"))
        .map(|(_, value)| value.trim());
    let user = if users.is_empty() {
        None
    } else if let Some(user) = authenticate_basic(authorization, users) {
        Some(user)
    } else {
        write_server_response(
            stream,
            407,
            "Proxy Authentication Required",
            &[("Proxy-Authenticate", "Basic realm=\"sing-box\"")],
        )
        .await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP proxy authentication failed",
        ));
    };
    let destination = target.parse::<SocksAddr>().map_err(|error| {
        invalid_input(format!("invalid HTTP CONNECT target: {error}"))
    })?;
    Ok((destination, user))
}

pub async fn write_connect_response<S>(
    stream: &mut S,
    success: bool,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    if success {
        write_server_response(stream, 200, "Connection established", &[]).await
    } else {
        write_server_response(stream, 502, "Bad Gateway", &[]).await
    }
}

async fn write_server_response<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let mut response = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

pub(crate) fn authenticate_basic(
    header: Option<&str>,
    users: &[User],
) -> Option<String> {
    let encoded = header?.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let (username, password) = decoded.split_at(separator);
    let password = &password[1..];
    users
        .iter()
        .find(|candidate| {
            constant_time_equal(candidate.username.as_bytes(), username)
                & constant_time_equal(candidate.password.as_bytes(), password)
        })
        .map(|user| user.username.clone())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0)
                ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

async fn read_header<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
) -> io::Result<String> {
    let mut bytes = Vec::with_capacity(512);
    loop {
        if bytes.len() == 64 * 1024 {
            return Err(invalid_data(
                "HTTP CONNECT response header is too large",
            ));
        }
        bytes.push(stream.read_u8().await?);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|_| {
                invalid_data("HTTP CONNECT response is not UTF-8")
            });
        }
    }
}

fn validate_header_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(invalid_input(format!(
            "invalid HTTP header name {name:?}"
        )));
    }
    Ok(())
}

fn append_header(
    request: &mut String,
    name: &str,
    value: &str,
) -> io::Result<()> {
    if value.contains(['\r', '\n']) {
        return Err(invalid_input(format!(
            "invalid newline in HTTP header {name:?}"
        )));
    }
    request.push_str(name);
    request.push_str(": ");
    request.push_str(value);
    request.push_str("\r\n");
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{client_handshake, server_handshake, write_connect_response};
    use crate::option::User;

    #[tokio::test]
    async fn connect_request_and_basic_auth_are_wire_exact() {
        let (mut client, mut server) = tokio::io::duplex(2048);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            loop {
                request.push(server.read_u8().await.unwrap());
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
            ));
            assert!(
                request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n")
            );
            assert!(request.contains("X-Test: one\r\nX-Test: two\r\n"));
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });
        client_handshake(
            &mut client,
            &"example.com:443".parse().unwrap(),
            Some(("user", "pass")),
            "",
            &json!({"X-Test": ["one", "two"]})
                .as_object()
                .unwrap()
                .clone(),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_auth_required_and_header_injection() {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut byte = [0];
            loop {
                server.read_exact(&mut byte).await.unwrap();
                if byte[0] == b'\n' {
                    let mut remaining = [0; 2];
                    if server.read_exact(&mut remaining).await.is_ok()
                        && remaining == *b"\r\n"
                    {
                        break;
                    }
                }
            }
            server
                .write_all(b"HTTP/1.1 407 Nope\r\n\r\n")
                .await
                .unwrap();
        });
        let error = client_handshake(
            &mut client,
            &"example.com:443".parse().unwrap(),
            None,
            "",
            &Map::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let mut headers = Map::new();
        headers.insert("X-Test".into(), json!("ok\r\nInjected: yes"));
        let (mut client, _server) = tokio::io::duplex(256);
        assert!(
            client_handshake(
                &mut client,
                &"example.com:443".parse().unwrap(),
                None,
                "",
                &headers,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn client_and_server_connect_handshakes_interoperate() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let users = [User {
                username: "user".into(),
                password: "pass".into(),
            }];
            let (destination, user) =
                server_handshake(&mut server, &users).await.unwrap();
            assert_eq!(destination.to_string(), "example.com:443");
            assert_eq!(user.as_deref(), Some("user"));
            write_connect_response(&mut server, true).await.unwrap();
        });
        client_handshake(
            &mut client,
            &"example.com:443".parse().unwrap(),
            Some(("user", "pass")),
            "",
            &Map::new(),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    use serde_json::Map;
}
