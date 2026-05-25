use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardKind {
    /// `ssh -L` — listen locally, connect from the SSH server.
    Local,
    /// `ssh -R` — listen on the SSH server, connect on this machine.
    Remote,
}

#[derive(Debug, Clone)]
pub struct SshForward {
    pub kind: ForwardKind,
    pub bind_host: String,
    pub bind_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

impl SshForward {
    pub fn parse(spec: &str, kind: ForwardKind) -> Result<Self> {
        let (bind_host, bind_port, dest_host, dest_port) =
            parse_forward_spec(spec)?;
        Ok(Self {
            kind,
            bind_host,
            bind_port,
            dest_host,
            dest_port,
        })
    }

    pub fn socket_addr(host: &str, port: u16) -> String {
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }
}

/// OpenSSH forward spec: `[bind_address:]port:host:hostport`
///
/// IPv6 addresses must use brackets, e.g. `[::1]:3307:[::1]:3306`.
fn parse_forward_spec(s: &str) -> Result<(String, u16, String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        bail!("forward spec must not be empty");
    }

    if !s.contains('[') {
        let parts: Vec<&str> = s.split(':').collect();
        return match parts.len() {
            3 => Ok((
                "127.0.0.1".to_string(),
                parts[0]
                    .parse()
                    .with_context(|| format!("invalid bind port in '{s}'"))?,
                parts[1].to_string(),
                parts[2].parse().with_context(|| {
                    format!("invalid destination port in '{s}'")
                })?,
            )),
            4 => Ok((
                parts[0].to_string(),
                parts[1]
                    .parse()
                    .with_context(|| format!("invalid bind port in '{s}'"))?,
                parts[2].to_string(),
                parts[3].parse().with_context(|| {
                    format!("invalid destination port in '{s}'")
                })?,
            )),
            _ => bail!(
                "invalid forward spec '{s}': expected [bind:]port:host:hostport \
                 (IPv6 requires brackets, e.g. [::1]:3307:[::1]:3306)"
            ),
        };
    }

    let (bind_host, bind_port, rest) = parse_host_port(s)
        .with_context(|| format!("invalid bind address in '{s}'"))?;
    let rest = rest
        .strip_prefix(':')
        .filter(|r| !r.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing destination in '{s}'"))?;
    let (dest_host, dest_port, tail) = parse_host_port(rest)
        .with_context(|| format!("invalid destination in '{s}'"))?;
    if !tail.is_empty() {
        bail!("unexpected trailing data in forward spec '{s}'");
    }

    Ok((bind_host, bind_port, dest_host, dest_port))
}

/// Parse `host:port` or `[ipv6]:port`, return remainder after the port.
fn parse_host_port(s: &str) -> Result<(String, u16, &str)> {
    let s = s.trim_start();
    if s.starts_with('[') {
        let end = s
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("missing ']' in IPv6 address"))?;
        let host = s[1..end].to_string();
        let rest = &s[end + 1..];
        if !rest.starts_with(':') {
            bail!("expected ':' after ']'");
        }
        let rest = &rest[1..];
        let port_end = rest.find(':').unwrap_or(rest.len());
        let port: u16 = rest[..port_end].parse().context("invalid port")?;
        Ok((host, port, &rest[port_end..]))
    } else {
        let colon = s
            .find(':')
            .ok_or_else(|| anyhow::anyhow!("missing ':' before port"))?;
        let host = s[..colon].to_string();
        if host.is_empty() {
            bail!("host must not be empty");
        }
        let rest = &s[colon + 1..];
        let port_end = rest.find(':').unwrap_or(rest.len());
        let port: u16 = rest[..port_end].parse().context("invalid port")?;
        Ok((host, port, &rest[port_end..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_three_part_local() {
        let (bh, bp, dh, dp) =
            parse_forward_spec("3307:10.0.0.5:3306").unwrap();
        assert_eq!(bh, "127.0.0.1");
        assert_eq!(bp, 3307);
        assert_eq!(dh, "10.0.0.5");
        assert_eq!(dp, 3306);
    }

    #[test]
    fn parse_four_part_local() {
        let (bh, bp, dh, dp) =
            parse_forward_spec("127.0.0.1:3307:10.0.0.5:3306").unwrap();
        assert_eq!(bh, "127.0.0.1");
        assert_eq!(bp, 3307);
        assert_eq!(dh, "10.0.0.5");
        assert_eq!(dp, 3306);
    }

    #[test]
    fn parse_ipv6_local() {
        let (bh, bp, dh, dp) =
            parse_forward_spec("[::1]:3307:[2001:db8::1]:3306").unwrap();
        assert_eq!(bh, "::1");
        assert_eq!(bp, 3307);
        assert_eq!(dh, "2001:db8::1");
        assert_eq!(dp, 3306);
    }

    #[test]
    fn parse_remote_same_format() {
        let fwd = SshForward::parse(
            "0.0.0.0:8080:127.0.0.1:3000",
            ForwardKind::Remote,
        )
        .unwrap();
        assert_eq!(fwd.bind_host, "0.0.0.0");
        assert_eq!(fwd.bind_port, 8080);
        assert_eq!(fwd.dest_host, "127.0.0.1");
        assert_eq!(fwd.dest_port, 3000);
    }
}
