use std::path::{Path, PathBuf};

use super::{
    ControlAuthCodec, ControlCryptCodec, ControlWrapError,
    OpenVpnTlsContextOptions, OpenVpnTlsError, TLS_CRYPT_KEY_DIRECTION_NORMAL,
    TlsControlProtection, TlsMaterial, build_openssl_tls_context,
    load_tls_crypt_v2_client_key, load_tls_crypt_v2_server_key,
    parse_openvpn_static_key, resolve_verify_client_cert_mode,
};
use crate::option::{
    Listable, OpenVpnClientEndpointOptions, OpenVpnControlWrapOptions,
    OpenVpnInboundControlWrapOptions, OpenVpnServerEndpointOptions,
};

pub struct OpenVpnClientSecurity {
    pub tls_context: openssl::ssl::SslContext,
    pub control_protection: TlsControlProtection,
    pub wrapped_client_key: Vec<u8>,
}

pub struct OpenVpnServerSecurity {
    pub tls_context: openssl::ssl::SslContext,
    pub control_protection: TlsControlProtection,
    pub force_cookie: bool,
}

pub fn build_openvpn_client_security(
    options: &OpenVpnClientEndpointOptions,
    base_path: &Path,
) -> Result<OpenVpnClientSecurity, OpenVpnEndpointBuildError> {
    options.validate().map_err(|error| {
        OpenVpnEndpointBuildError::Options(error.to_string())
    })?;
    let tls = options
        .tls
        .as_ref()
        .ok_or(OpenVpnEndpointBuildError::MissingTls)?;
    let tls_context = build_openssl_tls_context(&OpenVpnTlsContextOptions {
        certificate_authority: material(
            &tls.certificate,
            &tls.certificate_path,
            base_path,
        ),
        certificate: material(
            &tls.client_certificate,
            &tls.client_certificate_path,
            base_path,
        ),
        key: material(&tls.client_key, &tls.client_key_path, base_path),
        peer_fingerprints: tls.peer_fingerprint.as_slice().to_vec(),
        verify_name: tls.server_name.clone(),
        verify_name_type: tls.server_name_type.clone(),
        crl_path: resolved_path(&tls.crl_path, base_path),
        remote_certificate_ku: tls.remote_certificate_ku.as_slice().to_vec(),
        remote_certificate_eku: tls.remote_certificate_eku.clone(),
        remote_certificate_tls: tls.remote_certificate_tls.clone(),
        ns_certificate_type: tls.ns_certificate_type.clone(),
        version_min: tls.version_min.clone(),
        version_max: tls.version_max.clone(),
        cipher: tls.cipher.clone(),
        groups: tls.groups.clone(),
        certificate_profile: tls.certificate_profile.clone(),
        ..OpenVpnTlsContextOptions::client()
    })?;
    let (control_protection, wrapped_client_key) = match &tls.control_wrap {
        Some(wrap) => build_client_control_protection(wrap, base_path)?,
        None => (TlsControlProtection::default(), Vec::new()),
    };
    Ok(OpenVpnClientSecurity {
        tls_context,
        control_protection,
        wrapped_client_key,
    })
}

pub fn build_openvpn_server_security(
    options: &OpenVpnServerEndpointOptions,
    base_path: &Path,
) -> Result<OpenVpnServerSecurity, OpenVpnEndpointBuildError> {
    options.validate().map_err(|error| {
        OpenVpnEndpointBuildError::Options(error.to_string())
    })?;
    let tls = options
        .tls
        .as_ref()
        .ok_or(OpenVpnEndpointBuildError::MissingTls)?;
    let tls_context = build_openssl_tls_context(&OpenVpnTlsContextOptions {
        role: super::OpenVpnTlsRole::Server,
        certificate_authority: material(
            &tls.client_certificate,
            &tls.client_certificate_path,
            base_path,
        ),
        certificate: material(
            &tls.certificate,
            &tls.certificate_path,
            base_path,
        ),
        key: material(&tls.key, &tls.key_path, base_path),
        peer_fingerprints: tls.peer_fingerprint.as_slice().to_vec(),
        verify_name: tls.client_name.clone(),
        verify_name_type: tls.client_name_type.clone(),
        crl_path: resolved_path(&tls.crl_path, base_path),
        remote_certificate_ku: tls.remote_certificate_ku.as_slice().to_vec(),
        remote_certificate_eku: tls.remote_certificate_eku.clone(),
        remote_certificate_tls: tls.remote_certificate_tls.clone(),
        ns_certificate_type: tls.ns_certificate_type.clone(),
        verify_client_certificate: resolve_verify_client_cert_mode(
            &tls.verify_client_certificate,
        )?,
        version_min: tls.version_min.clone(),
        version_max: tls.version_max.clone(),
        cipher: tls.cipher.clone(),
        groups: tls.groups.clone(),
        certificate_profile: tls.certificate_profile.clone(),
    })?;
    let (control_protection, force_cookie) = match &tls.control_wrap {
        Some(wrap) => build_server_control_protection(wrap, base_path)?,
        None => (TlsControlProtection::default(), false),
    };
    Ok(OpenVpnServerSecurity {
        tls_context,
        control_protection,
        force_cookie,
    })
}

pub fn load_openvpn_static_key_material(
    values: &Listable<String>,
    path: &str,
    base_path: &Path,
) -> Result<Vec<u8>, OpenVpnEndpointBuildError> {
    let content = material(values, path, base_path)
        .load()?
        .ok_or(OpenVpnEndpointBuildError::MissingStaticKey)?;
    parse_openvpn_static_key(&content).map_err(OpenVpnEndpointBuildError::from)
}

pub fn resolve_openvpn_key_direction(direction: &str) -> i8 {
    key_direction(direction)
}

fn build_client_control_protection(
    wrap: &OpenVpnControlWrapOptions,
    base_path: &Path,
) -> Result<(TlsControlProtection, Vec<u8>), OpenVpnEndpointBuildError> {
    let key = load_material(&wrap.key, &wrap.key_path, base_path)?;
    let direction = key_direction(&wrap.direction);
    match wrap.kind.as_str() {
        "tls_auth" => Ok((
            TlsControlProtection {
                auth: Some(ControlAuthCodec::new(&key, direction, "SHA1")?),
                ..TlsControlProtection::default()
            },
            Vec::new(),
        )),
        "tls_crypt" => Ok((
            TlsControlProtection {
                crypt: Some(ControlCryptCodec::new(
                    &key,
                    TLS_CRYPT_KEY_DIRECTION_NORMAL,
                )?),
                ..TlsControlProtection::default()
            },
            Vec::new(),
        )),
        "tls_crypt_v2" => {
            let (material, wrapped) = load_tls_crypt_v2_client_key(&key)?;
            Ok((
                TlsControlProtection {
                    crypt: Some(ControlCryptCodec::from_material(
                        &material,
                        TLS_CRYPT_KEY_DIRECTION_NORMAL,
                    )?),
                    ..TlsControlProtection::default()
                },
                wrapped,
            ))
        }
        kind => Err(OpenVpnEndpointBuildError::ControlWrapType(kind.into())),
    }
}

fn build_server_control_protection(
    wrap: &OpenVpnInboundControlWrapOptions,
    base_path: &Path,
) -> Result<(TlsControlProtection, bool), OpenVpnEndpointBuildError> {
    let key = load_material(&wrap.key, &wrap.key_path, base_path)?;
    let direction = key_direction(&wrap.direction);
    let protection = match wrap.kind.as_str() {
        "tls_auth" => TlsControlProtection {
            auth: Some(ControlAuthCodec::new(&key, direction, "SHA1")?),
            ..TlsControlProtection::default()
        },
        "tls_crypt" => TlsControlProtection {
            crypt: Some(ControlCryptCodec::new(
                &key,
                TLS_CRYPT_KEY_DIRECTION_NORMAL,
            )?),
            ..TlsControlProtection::default()
        },
        "tls_crypt_v2" => TlsControlProtection {
            crypt_v2_server_key: load_tls_crypt_v2_server_key(&key)?,
            ..TlsControlProtection::default()
        },
        kind => {
            return Err(OpenVpnEndpointBuildError::ControlWrapType(
                kind.into(),
            ));
        }
    };
    Ok((protection, wrap.force_cookie))
}

fn material(values: &Listable<String>, path: &str, base: &Path) -> TlsMaterial {
    if !path.is_empty() {
        TlsMaterial {
            path: Some(resolve_path(path, base)),
            content: Vec::new(),
        }
    } else {
        TlsMaterial::from_pem(values.as_slice().join("\n"))
    }
}

fn load_material(
    values: &Listable<String>,
    path: &str,
    base: &Path,
) -> Result<Vec<u8>, OpenVpnEndpointBuildError> {
    material(values, path, base)
        .load()?
        .ok_or(OpenVpnEndpointBuildError::MissingControlKey)
}

fn resolve_path(path: &str, base: &Path) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

fn resolved_path(path: &str, base: &Path) -> String {
    if path.is_empty() {
        String::new()
    } else {
        resolve_path(path, base).to_string_lossy().into_owned()
    }
}

fn key_direction(direction: &str) -> i8 {
    match direction {
        "server" => 0,
        "client" => 1,
        _ => -1,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenVpnEndpointBuildError {
    #[error("invalid OpenVPN endpoint options: {0}")]
    Options(String),
    #[error("OpenVPN TLS options are required")]
    MissingTls,
    #[error("OpenVPN control-wrap key is required")]
    MissingControlKey,
    #[error("OpenVPN static key is required")]
    MissingStaticKey,
    #[error("unsupported OpenVPN control-wrap type: {0}")]
    ControlWrapType(String),
    #[error(transparent)]
    Tls(#[from] OpenVpnTlsError),
    #[error(transparent)]
    ControlWrap(#[from] ControlWrapError),
    #[error(transparent)]
    DataCodec(#[from] super::OpenVpnDataCodecError),
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};

    use super::*;

    #[test]
    fn maps_endpoint_tls_material_into_client_and_server_contexts() {
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["vpn.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        let client: OpenVpnClientEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "server": "vpn.test",
                "server_port": 1194,
                "tls": {
                    "server_name": "vpn.test",
                    "certificate": certificate
                }
            }))
            .unwrap();
        let server: OpenVpnServerEndpointOptions =
            serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "listen_port": 1194,
                "address": "10.8.0.1/24",
                "tls": {
                    "certificate": certificate,
                    "key": key.serialize_pem(),
                    "verify_client_certificate": "none"
                }
            }))
            .unwrap();
        let client =
            build_openvpn_client_security(&client, Path::new(".")).unwrap();
        let server =
            build_openvpn_server_security(&server, Path::new(".")).unwrap();
        assert!(client.wrapped_client_key.is_empty());
        assert!(!server.force_cookie);
    }
}
