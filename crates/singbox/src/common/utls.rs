//! sing-box's uTLS fingerprint selection on top of the shared rustls shaper.

use std::sync::{Arc, OnceLock};

use rand::{Rng as _, RngCore as _, rngs::OsRng};
use rustls::{
    ClientConfig, Error as RustlsError, NamedGroup, SupportedProtocolVersion,
    client::{
        ClientHelloAdvertisedSupportedGroups, ClientHelloContext,
        ClientHelloCustomizer, ClientHelloExtensionOrder,
        ClientHelloKeySharePlan, ClientHelloPlan, ClientHelloSessionId,
        ClientHelloSupportedGroups,
    },
};

use super::{
    utls_profiles::{
        UtlsClientHelloProfile, chrome_quic_profile, profile_for_fingerprint,
    },
    utls_shaping::{
        apply_alpn_override, apply_utls_profile, profile_offers_tls13,
    },
};

const PROCESS_RANDOM_FINGERPRINTS: &[&str] = &[
    "hellochrome_133",
    "hellofirefox_120",
    "helloedge_85",
    "hellosafari_16_0",
    "helloios_14",
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum UtlsError {
    #[error("unknown uTLS fingerprint: {0}")]
    UnknownFingerprint(String),
}

#[derive(Debug)]
pub(crate) struct SingBoxUtlsCustomizer {
    profile: &'static UtlsClientHelloProfile,
    shuffle_chrome_extensions: bool,
    chrome_quic: bool,
}

impl SingBoxUtlsCustomizer {
    pub(crate) fn resolve(
        fingerprint: &str,
    ) -> Result<(Arc<Self>, bool), UtlsError> {
        let profile_name = resolve_profile_name(fingerprint)?;
        let profile =
            profile_for_fingerprint(profile_name).ok_or_else(|| {
                UtlsError::UnknownFingerprint(fingerprint.to_owned())
            })?;
        Ok((
            Arc::new(Self {
                profile,
                shuffle_chrome_extensions: profile_name == "hellochrome_133",
                chrome_quic: false,
            }),
            profile_offers_tls13(profile),
        ))
    }

    pub(crate) fn chrome_quic() -> Arc<Self> {
        Arc::new(Self {
            profile: chrome_quic_profile(),
            shuffle_chrome_extensions: true,
            chrome_quic: true,
        })
    }

    pub(crate) fn configure(&self, config: &mut ClientConfig) {
        super::utls_shaping::retain_profile_certificate_decompressors(
            self.profile,
            &mut config.cert_decompressors,
        );
    }

    pub(crate) fn is_negotiable(
        &self,
        provider: &rustls::crypto::CryptoProvider,
        versions: &[&'static SupportedProtocolVersion],
    ) -> bool {
        provider.cipher_suites.iter().any(|suite| {
            self.profile
                .cipher_suites
                .contains(&u16::from(suite.suite()))
                && versions
                    .iter()
                    .any(|version| version.version == suite.version().version)
        })
    }

    fn build_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<ClientHelloPlan, RustlsError> {
        let mut plan =
            apply_utls_profile(ClientHelloPlan::new(), self.profile, context)?;
        if self.shuffle_chrome_extensions {
            plan = plan
                .with_extension_order(chrome_extension_order(self.profile)?);
        }
        if !profile_offers_tls13(self.profile) {
            plan = plan.with_session_id(random_session_id()?);
        }
        if !context.alpn_protocols.is_empty() {
            plan = apply_alpn_override(
                plan,
                self.profile,
                context.alpn_protocols,
            )?;
        }
        Ok(plan)
    }

    pub(crate) fn build_reality_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<ClientHelloPlan, RustlsError> {
        if !profile_offers_tls13(self.profile) {
            return Err(RustlsError::General(
                "REALITY requires a TLS 1.3 uTLS fingerprint".into(),
            ));
        }
        let mut plan = self.build_plan(context)?;

        // Pinned sing-box removes X25519MLKEM768 from the selected uTLS
        // profile before binding REALITY's ephemeral key.
        let advertised_groups = self
            .profile
            .supported_groups
            .iter()
            .copied()
            .filter(|group| *group != 0x11ec)
            .map(NamedGroup::from)
            .collect::<Vec<_>>();
        let supported_groups = advertised_groups
            .iter()
            .copied()
            .filter(|group| !is_grease_value(u16::from(*group)))
            .collect::<Vec<_>>();
        plan = plan
            .with_advertised_supported_groups(
                ClientHelloAdvertisedSupportedGroups::try_from(
                    advertised_groups,
                )?,
            )
            .with_supported_groups(ClientHelloSupportedGroups::try_from(
                supported_groups,
            )?)
            .with_key_share_plan(ClientHelloKeySharePlan::try_from(vec![
                NamedGroup::X25519,
            ])?);
        Ok(plan)
    }
}

impl ClientHelloCustomizer for SingBoxUtlsCustomizer {
    fn build_client_hello_plan(
        &self,
        context: ClientHelloContext<'_>,
    ) -> Result<Option<ClientHelloPlan>, RustlsError> {
        if context.is_quic != self.chrome_quic {
            return Ok(None);
        }
        self.build_plan(context).map(Some)
    }
}

fn chrome_extension_order(
    profile: &UtlsClientHelloProfile,
) -> Result<ClientHelloExtensionOrder, RustlsError> {
    const PADDING: u16 = 0x0015;
    const PRE_SHARED_KEY: u16 = 0x0029;

    let mut extensions = profile
        .extensions
        .iter()
        .map(|extension| extension.extension_type)
        .collect::<Vec<_>>();
    let invariant = |extension: u16| {
        is_grease_value(extension)
            || matches!(extension, PADDING | PRE_SHARED_KEY)
    };
    for index in (1..extensions.len()).rev() {
        let swap_with = OsRng.gen_range(0..=index);
        if !invariant(extensions[index]) && !invariant(extensions[swap_with]) {
            extensions.swap(index, swap_with);
        }
    }
    extensions.retain(|extension| !is_grease_value(*extension));
    ClientHelloExtensionOrder::try_from(extensions)
}

fn is_grease_value(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn resolve_profile_name(fingerprint: &str) -> Result<&'static str, UtlsError> {
    Ok(match fingerprint {
        ""
        | "chrome"
        | "chrome_psk"
        | "chrome_psk_shuffle"
        | "chrome_padding_psk_shuffle"
        | "chrome_pq"
        | "chrome_pq_psk" => "hellochrome_133",
        "firefox" => "hellofirefox_120",
        "edge" => "helloedge_85",
        "safari" => "hellosafari_16_0",
        "360" => "hello360_7_5",
        "qq" => "helloqq_11_1",
        "ios" => "helloios_14",
        "android" => "helloandroid_11_okhttp",
        "random" => process_random_fingerprint(),
        "randomized" => "randomized",
        other => return Err(UtlsError::UnknownFingerprint(other.to_owned())),
    })
}

fn process_random_fingerprint() -> &'static str {
    static DRAWN: OnceLock<&'static str> = OnceLock::new();
    DRAWN.get_or_init(|| {
        let mut entropy = [0; 8];
        if OsRng.try_fill_bytes(&mut entropy).is_err() {
            return PROCESS_RANDOM_FINGERPRINTS[0];
        }
        let index = u64::from_ne_bytes(entropy) as usize
            % PROCESS_RANDOM_FINGERPRINTS.len();
        PROCESS_RANDOM_FINGERPRINTS[index]
    })
}

fn random_session_id() -> Result<ClientHelloSessionId, RustlsError> {
    let mut session_id = vec![0; 32];
    OsRng
        .try_fill_bytes(&mut session_id)
        .map_err(|error| RustlsError::General(error.to_string()))?;
    ClientHelloSessionId::try_from(session_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_match_pinned_sing_box_switch() {
        for alias in [
            "",
            "chrome",
            "chrome_psk",
            "chrome_psk_shuffle",
            "chrome_padding_psk_shuffle",
            "chrome_pq",
            "chrome_pq_psk",
        ] {
            assert_eq!(resolve_profile_name(alias), Ok("hellochrome_133"));
        }
        assert_eq!(resolve_profile_name("firefox"), Ok("hellofirefox_120"));
        assert_eq!(resolve_profile_name("safari"), Ok("hellosafari_16_0"));
    }

    #[test]
    fn random_is_stable_for_the_process_and_uses_sing_box_pool() {
        let selected = resolve_profile_name("random").unwrap();
        assert!(PROCESS_RANDOM_FINGERPRINTS.contains(&selected));
        assert_eq!(resolve_profile_name("random"), Ok(selected));
    }

    #[test]
    fn randomized_resolves_to_one_stable_tls13_shape_per_process() {
        assert_eq!(resolve_profile_name("randomized"), Ok("randomized"));
        let first = profile_for_fingerprint("randomized").unwrap();
        let second = profile_for_fingerprint("randomized").unwrap();
        assert!(std::ptr::eq(first, second));
        assert!(profile_offers_tls13(first));
        assert_eq!(first.supported_versions[0], 0x0304);
        assert!(
            first
                .extensions
                .iter()
                .any(|extension| { extension.extension_type == 0x0015 })
        );
        assert!(
            !first
                .cipher_suites
                .iter()
                .any(|suite| { matches!(*suite, 0x0005 | 0xc011 | 0xc007) })
        );
        assert_ne!(first.key_shares[0].group, 0x0017);
    }

    #[test]
    fn unknown_fingerprint_fails_closed() {
        assert_eq!(
            resolve_profile_name("made-up"),
            Err(UtlsError::UnknownFingerprint("made-up".into()))
        );
    }
}
