use anyhow::Result;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use clap::ValueEnum;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::json;

use super::{clash_configuration, server_uri};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum QrFormat {
    /// Configuration URL for Clash/Mihomo and Zay's in-app scanners.
    Clash,
    /// Open Clash through a system camera or browser.
    ClashImport,
    /// Standard percent-encoded SOCKS5 URI.
    Socks,
    /// Base64 credential SOCKS URI used by v2rayNG/v2rayN.
    V2ray,
    /// Shadowrocket SOCKS node link; scan inside Shadowrocket.
    Shadowrocket,
    /// Add a Quantumult X server subscription without replacing settings.
    #[value(alias = "quantumx", alias = "quanx")]
    QuantumultX,
    /// Remote profile import for sing-box graphical clients (1.12+).
    SingBox,
    /// Telegram SOCKS proxy link.
    Telegram,
    /// Browser page with all available import links and downloads.
    Browser,
    /// Print every available QR format.
    All,
    /// Print links without QR codes.
    None,
}

pub struct ShareLink {
    pub format: QrFormat,
    pub label: &'static str,
    pub url: String,
}

pub struct Resource {
    pub path: String,
    pub content_type: &'static str,
    pub body: String,
}

pub fn build(
    base: &str,
    path: &str,
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(Vec<ShareLink>, Vec<Resource>)> {
    let clash = format!("{base}/clash.yaml");
    let sing_box = format!("{base}/sing-box.json");
    let quantumult = quantumult_configuration(host, port, username, password);
    let mut links = vec![
        ShareLink {
            format: QrFormat::Clash,
            label: "Clash / Zay import URL",
            url: clash.clone(),
        },
        ShareLink {
            format: QrFormat::ClashImport,
            label: "Clash app import",
            url: format!(
                "clash://install-config?url={}&name=s5",
                encode(&clash)
            ),
        },
        ShareLink {
            format: QrFormat::Socks,
            label: "SOCKS URL",
            url: server_uri(host, port, username, password),
        },
        ShareLink {
            format: QrFormat::SingBox,
            label: "sing-box app import",
            url: format!(
                "sing-box://import-remote-profile?url={}#s5",
                encode(&sing_box)
            ),
        },
        ShareLink {
            format: QrFormat::Telegram,
            label: "Telegram proxy",
            url: telegram_uri(host, port, username, password),
        },
        ShareLink {
            format: QrFormat::Browser,
            label: "Browser import page",
            url: format!("{base}/"),
        },
    ];
    // These clients split decoded user:password at the first colon. A colon
    // in a username is ambiguous; JSON downloads preserve such credentials.
    if let Some(url) = v2ray_uri(host, port, username, password) {
        links.insert(
            3,
            ShareLink {
                format: QrFormat::V2ray,
                label: "v2ray SOCKS URL",
                url,
            },
        );
    }
    if let Some(url) = shadowrocket_uri(host, port, username, password) {
        links.push(ShareLink {
            format: QrFormat::Shadowrocket,
            label: "Shadowrocket SOCKS node",
            url,
        });
    }
    if quantumult.is_some() {
        let resource = json!({ "server_remote": [format!("{base}/quantumult-x.txt, tag=s5, enabled=true")] });
        links.push(ShareLink {
            format: QrFormat::QuantumultX,
            label: "Quantumult X server subscription",
            url: format!("https://quantumult.app/x/open-app/add-resource?remote-resource={}", encode(&resource.to_string())),
        });
    }
    let mut proxy = json!({ "type": "socks", "tag": "s5", "server": host, "server_port": port, "version": "5" });
    let mut xray_server = json!({ "address": host, "port": port });
    if let (Some(username), Some(password)) = (username, password) {
        proxy["username"] = json!(username);
        proxy["password"] = json!(password);
        xray_server["users"] = json!([{ "user": username, "pass": password }]);
    }
    let sing_box_profile = json!({
        "dns": { "servers": [
            { "type": "local", "tag": "bootstrap" },
            { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "s5" }
        ], "final": "remote" },
        "inbounds": [{ "type": "tun", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "auto_route": true, "strict_route": true }],
        "outbounds": [proxy],
        "route": { "rules": [{ "protocol": "dns", "action": "hijack-dns" }], "final": "s5", "auto_detect_interface": true, "default_domain_resolver": "bootstrap" }
    });
    let xray_profile = json!({
        "inbounds": [{ "listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": { "auth": "noauth", "udp": true } }],
        "outbounds": [{ "tag": "s5", "protocol": "socks", "settings": { "servers": [xray_server] } }]
    });
    let page = import_page(base, &links);
    let text = links
        .iter()
        .map(|link| format!("{}: {}\n", link.label, link.url))
        .collect::<String>();
    let mut resources = vec![
        Resource {
            path: format!("{path}/clash.yaml"),
            content_type: "application/yaml; charset=utf-8",
            body: clash_configuration(host, port, username, password)?,
        },
        Resource {
            path: format!("{path}/sing-box.json"),
            content_type: "application/json; charset=utf-8",
            body: serde_json::to_string_pretty(&sing_box_profile)?,
        },
        Resource {
            path: format!("{path}/xray.json"),
            content_type: "application/json; charset=utf-8",
            body: serde_json::to_string_pretty(&xray_profile)?,
        },
        Resource {
            path: format!("{path}/links.txt"),
            content_type: "text/plain; charset=utf-8",
            body: text,
        },
        Resource {
            path: format!("{path}/"),
            content_type: "text/html; charset=utf-8",
            body: page,
        },
    ];
    if let Some(body) = quantumult {
        resources.push(Resource {
            path: format!("{path}/quantumult-x.txt"),
            content_type: "text/plain; charset=utf-8",
            body,
        });
    }
    Ok((links, resources))
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn shadowrocket_uri(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Option<String> {
    // Legacy node parsers split decoded credentials at ':' and '@'. Avoid
    // exporting credentials that those clients could silently truncate.
    let credentials = match (username, password) {
        (Some(user), Some(pass))
            if !user.contains([':', '@']) && !pass.contains([':', '@']) =>
        {
            format!("{user}:{pass}")
        }
        (None, None) => ":".to_owned(),
        _ => return None,
    };
    Some(format!(
        "socks://{}?remarks=s5",
        URL_SAFE_NO_PAD
            .encode(format!("{credentials}@{}", authority(host, port)))
    ))
}

fn quantumult_configuration(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Option<String> {
    let mut line = format!("socks5={}", authority(host, port));
    match (username, password) {
        (Some(user), Some(pass)) => {
            // The native snippet syntax has no documented credential escaping.
            if [user, pass].iter().any(|value| {
                value.trim() != *value
                    || value.contains([',', '=', '"', '\''])
                    || value.chars().any(char::is_control)
            }) {
                return None;
            }
            line.push_str(&format!(", username={user}, password={pass}"));
        }
        (None, None) => {}
        _ => return None,
    }
    line.push_str(
        ", over-tls=false, udp-relay=true, fast-open=false, tag=s5\n",
    );
    Some(line)
}

fn encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

pub fn v2ray_uri(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Option<String> {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let credentials = match (username, password) {
        (Some(username), Some(password)) if !username.contains(':') => format!(
            "{}@",
            encode(&STANDARD_NO_PAD.encode(format!("{username}:{password}")))
        ),
        (None, None) => String::new(),
        _ => return None,
    };
    Some(format!("socks://{credentials}{host}:{port}#s5"))
}

pub fn telegram_uri(
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> String {
    let mut uri =
        format!("https://t.me/socks?server={}&port={port}", encode(host));
    if let (Some(username), Some(password)) = (username, password) {
        uri.push_str(&format!(
            "&user={}&pass={}",
            encode(username),
            encode(password)
        ));
    }
    uri
}

fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn import_page(base: &str, links: &[ShareLink]) -> String {
    let mut page = String::from(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Import s5</title><style>body{font:17px system-ui;max-width:700px;margin:32px auto;padding:0 20px}li{margin:20px 0}code{display:block;overflow-wrap:anywhere;font-size:13px}a{color:#1766ce}</style><h1>Import s5</h1><p>Choose your app or copy its import URL.</p><ul>",
    );
    for link in links.iter().filter(|link| link.format != QrFormat::Browser) {
        page.push_str(&format!(
            "<li><a href=\"{}\">{}</a><code>{}</code></li>",
            html(&link.url),
            link.label,
            html(&link.url)
        ));
        if link.format == QrFormat::QuantumultX {
            let custom = link.url.replace(
                "https://quantumult.app/x/open-app/add-resource",
                "quantumult-x:///add-resource",
            );
            page.push_str(&format!("<li><a href=\"{}\">Quantumult X app import (1.0.29+)</a><code>{}</code></li>", html(&custom), html(&custom)));
        }
    }
    page.push_str("</ul><h2>Download a profile</h2><ul>");
    if links
        .iter()
        .any(|link| link.format == QrFormat::QuantumultX)
    {
        page.push_str(&format!("<li><a download href=\"{}/quantumult-x.txt\">Quantumult X server snippet</a></li>", html(base)));
    }
    for (file, label) in [
        ("clash.yaml", "Clash / Mihomo YAML"),
        ("sing-box.json", "sing-box JSON (1.12+)"),
        ("xray.json", "Xray / V2Ray JSON"),
        ("links.txt", "All import links"),
    ] {
        page.push_str(&format!(
            "<li><a download href=\"{}/{}\">{label}</a></li>",
            html(base),
            file
        ));
    }
    page.push_str("</ul><p>Keep this page private: these links include your server credentials.</p></html>");
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ios_formats_preserve_nodes_and_add_resources() {
        for (host, user, pass) in [
            ("proxy.example.com", Some("alice"), Some("p%/&λ")),
            ("2001:db8::5", None, None),
        ] {
            let (links, resources) = build(
                "http://host:1081/token",
                "/token",
                host,
                2345,
                user,
                pass,
            )
            .unwrap();
            let shadowrocket = &links
                .iter()
                .find(|link| link.format == QrFormat::Shadowrocket)
                .unwrap()
                .url;
            let encoded = shadowrocket
                .strip_prefix("socks://")
                .unwrap()
                .strip_suffix("?remarks=s5")
                .unwrap();
            let node =
                String::from_utf8(URL_SAFE_NO_PAD.decode(encoded).unwrap())
                    .unwrap();
            assert_eq!(
                node,
                format!(
                    "{}:{}@{}",
                    user.unwrap_or(""),
                    pass.unwrap_or(""),
                    authority(host, 2345)
                )
            );
            let quantumult = &links
                .iter()
                .find(|link| link.format == QrFormat::QuantumultX)
                .unwrap()
                .url;
            let encoded = quantumult.strip_prefix("https://quantumult.app/x/open-app/add-resource?remote-resource=").unwrap();
            let resource: serde_json::Value = serde_json::from_str(
                &percent_encoding::percent_decode_str(encoded)
                    .decode_utf8()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                resource,
                json!({"server_remote":["http://host:1081/token/quantumult-x.txt, tag=s5, enabled=true"]})
            );
            let body = &resources
                .iter()
                .find(|resource| resource.path.ends_with("quantumult-x.txt"))
                .unwrap()
                .body;
            assert!(
                body.starts_with(&format!("socks5={}", authority(host, 2345)))
            );
            assert!(body.contains("udp-relay=true"));
            assert_eq!(body.contains("username="), user.is_some());
            assert!(
                resources
                    .iter()
                    .find(|resource| resource.path.ends_with('/'))
                    .unwrap()
                    .body
                    .contains("Quantumult X server snippet")
            );
        }
        assert!(
            shadowrocket_uri("host", 1080, Some("alice"), Some("p:@"))
                .is_none()
        );
        for credential in ["a,b", "a=b", "a\nb", " padded ", "a\"b", "a'b"] {
            let (links, resources) = build(
                "http://host/token",
                "/token",
                "host",
                1080,
                Some("alice"),
                Some(credential),
            )
            .unwrap();
            assert!(
                !links
                    .iter()
                    .any(|link| link.format == QrFormat::QuantumultX)
            );
            assert!(
                !resources.iter().any(|resource| resource
                    .path
                    .ends_with("quantumult-x.txt"))
            );
            assert!(links.iter().any(|link| link.format == QrFormat::Socks));
        }
        assert!(
            quantumult_configuration("host", 1080, Some("a:b"), Some("p:@/%λ"))
                .unwrap()
                .contains("username=a:b, password=p:@/%λ")
        );
    }

    #[test]
    fn v2ray_preserves_utf8_and_password_delimiters() {
        let uri = v2ray_uri(
            "2001:db8::5",
            1080,
            Some("alice"),
            Some("p:@/\"&<>'\nλ"),
        )
        .unwrap();
        let userinfo = uri
            .strip_prefix("socks://")
            .unwrap()
            .split('@')
            .next()
            .unwrap();
        let decoded = STANDARD_NO_PAD
            .decode(
                percent_encoding::percent_decode_str(userinfo)
                    .decode_utf8()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "alice:p:@/\"&<>'\nλ");
        assert!(uri.ends_with("@[2001:db8::5]:1080#s5"));
        assert!(
            v2ray_uri("host", 1080, Some("a:b"), Some("password")).is_none()
        );
        assert_eq!(
            v2ray_uri("host", 1080, None, None).unwrap(),
            "socks://host:1080#s5"
        );
    }

    #[test]
    fn browser_links_are_escaped_and_unsupported_formats_are_omitted() {
        let (links, resources) = build(
            "http://host:1081/token",
            "/token",
            "host",
            1080,
            Some("a:b"),
            Some("p&\"<"),
        )
        .unwrap();
        assert!(!links.iter().any(|link| link.format == QrFormat::V2ray));
        assert!(links.iter().any(|link| link.format == QrFormat::Clash));
        assert!(links.iter().any(|link| link.format == QrFormat::SingBox));
        let page = &resources
            .iter()
            .find(|resource| resource.path.ends_with('/'))
            .unwrap()
            .body;
        assert!(page.contains("&amp;user="));
        assert!(!page.contains("p&\"<"));
        assert!(page.contains("xray.json"));
        assert_eq!(
            telegram_uri("2001:db8::5", 1080, Some("a:b"), Some("p&?")),
            "https://t.me/socks?server=2001%3Adb8%3A%3A5&port=1080&user=a%3Ab&pass=p%26%3F"
        );
    }
}
