use tonic::{Request, metadata::MetadataMap};

/// Locale selected from daemon request metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedLocale(&'static str);

impl SelectedLocale {
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// Apply the first usable `accept-language` metadata value to request
/// extensions, where StartedService handlers can retrieve it.
pub fn apply_request_locale<T>(request: &mut Request<T>) {
    if let Some(locale) = select_locale_from_metadata(request.metadata()) {
        request.extensions_mut().insert(SelectedLocale(locale));
    }
}

pub fn request_locale<T>(request: &Request<T>) -> &'static str {
    request
        .extensions()
        .get::<SelectedLocale>()
        .copied()
        .unwrap_or(SelectedLocale("en"))
        .as_str()
}

fn select_locale_from_metadata(metadata: &MetadataMap) -> Option<&'static str> {
    metadata
        .get_all("accept-language")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(select_locale)
}

/// Match sing-box's five daemon locales and its common POSIX/Chinese aliases.
/// Unknown but syntactically valid language tags fall back to English, just as
/// the upstream `language.Matcher` does.
pub fn select_locale(accept_language: &str) -> Option<&'static str> {
    let mut entries = accept_language
        .split(',')
        .enumerate()
        .filter_map(|(index, entry)| parse_entry(index, entry))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .quality
            .total_cmp(&left.quality)
            .then(left.index.cmp(&right.index))
    });
    entries
        .into_iter()
        .find_map(|entry| match_language(&entry.language))
}

struct LanguageEntry {
    index: usize,
    quality: f32,
    language: String,
}

fn parse_entry(index: usize, entry: &str) -> Option<LanguageEntry> {
    let (language, options) = entry.split_once(';').unwrap_or((entry, ""));
    let mut language = language.trim().split('@').next()?.replace('_', "-");
    if options.is_empty() {
        language.truncate(language.find('.').unwrap_or(language.len()));
    }
    if language.is_empty() {
        return None;
    }
    let mut quality = 1.0_f32;
    for option in options.split(';').map(str::trim) {
        let Some(value) = option.strip_prefix("q=") else {
            continue;
        };
        quality = value.parse().ok()?;
    }
    if !(0.0..=1.0).contains(&quality) || quality == 0.0 {
        return None;
    }
    Some(LanguageEntry {
        index,
        quality,
        language,
    })
}

fn match_language(language: &str) -> Option<&'static str> {
    if language.eq_ignore_ascii_case("c")
        || language.eq_ignore_ascii_case("posix")
    {
        return Some("en");
    }
    let language = if language.eq_ignore_ascii_case("zh-chs") {
        "zh-Hans"
    } else if language.eq_ignore_ascii_case("zh-cht") {
        "zh-Hant"
    } else {
        language
    };
    if language == "*" {
        return Some("en");
    }
    if !language.split('-').all(|part| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }) {
        return None;
    }
    let parts = language.split('-').collect::<Vec<_>>();
    let primary = parts[0];
    if primary.eq_ignore_ascii_case("zh") || primary.eq_ignore_ascii_case("cmn")
    {
        if parts.iter().any(|part| {
            part.eq_ignore_ascii_case("hant")
                || part.eq_ignore_ascii_case("tw")
                || part.eq_ignore_ascii_case("hk")
                || part.eq_ignore_ascii_case("mo")
        }) {
            return Some("zh-Hant");
        }
        return Some("zh-Hans");
    }
    if primary.eq_ignore_ascii_case("fa") {
        return Some("fa");
    }
    if primary.eq_ignore_ascii_case("ru") {
        return Some("ru");
    }
    Some("en")
}

#[cfg(test)]
mod tests {
    use tonic::{Request, service::Interceptor as _};

    use super::{request_locale, select_locale};
    use crate::daemon::{ClientAuthInterceptor, ServerAuthInterceptor};

    #[test]
    fn locale_alias_quality_and_metadata_match_upstream() {
        for (input, expected) in [
            ("C", Some("en")),
            ("POSIX", Some("en")),
            ("zh_CN.UTF-8", Some("zh-Hans")),
            ("zh-CHS", Some("zh-Hans")),
            ("zh_HK", Some("zh-Hant")),
            ("zh-CHT", Some("zh-Hant")),
            ("fa-IR", Some("fa")),
            ("ru-RU", Some("ru")),
            ("fr-FR", Some("en")),
            ("ru;q=0.2, zh-TW;q=0.9", Some("zh-Hant")),
            ("@@@", None),
        ] {
            assert_eq!(select_locale(input), expected, "input {input:?}");
        }

        let request = ClientAuthInterceptor::new_with_locale("secret", "zh-TW")
            .unwrap()
            .call(Request::new(()))
            .unwrap();
        assert_eq!(request.metadata().get("accept-language").unwrap(), "zh-TW");
        let request =
            ServerAuthInterceptor::new("secret").call(request).unwrap();
        assert_eq!(request_locale(&request), "zh-Hant");
    }
}
