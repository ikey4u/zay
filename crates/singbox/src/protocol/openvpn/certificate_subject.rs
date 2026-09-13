use openssl::{asn1::Asn1Object, nid::Nid};

pub const CERTIFICATE_USERNAME_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DistinguishedNameAttribute {
    oid: String,
    tag: u8,
    value: Vec<u8>,
}

pub fn format_certificate_subject(
    raw_subject: &[u8],
) -> Result<String, CertificateSubjectError> {
    let names = parse_distinguished_name(raw_subject)?;
    let mut rendered = Vec::new();
    let mut rendered_count = 0;
    for attributes in names {
        for (index, attribute) in attributes.into_iter().enumerate() {
            if rendered_count > 0 {
                rendered.extend_from_slice(if index > 0 {
                    b" + "
                } else {
                    b", "
                });
            }
            rendered_count += 1;
            rendered.extend_from_slice(
                openssl_attribute_type_name(&attribute.oid).as_bytes(),
            );
            rendered.push(b'=');
            rendered.extend_from_slice(&print_attribute_value(
                attribute.tag,
                &attribute.value,
            )?);
        }
    }
    if rendered_count == 0 {
        return Err(CertificateSubjectError::EmptySubject);
    }
    Ok(String::from_utf8_lossy(&rendered).into_owned())
}

pub fn certificate_username(
    raw_subject: &[u8],
    attribute_oid: &str,
) -> Result<String, CertificateSubjectError> {
    let names = parse_distinguished_name(raw_subject)?;
    let selected = names
        .into_iter()
        .flatten()
        .rfind(|attribute| attribute.oid == attribute_oid)
        .ok_or_else(|| {
            CertificateSubjectError::MissingAttribute(
                openssl_attribute_type_name(attribute_oid),
            )
        })?;
    let width = openssl_character_width(selected.tag);
    if width < 0 {
        return Err(CertificateSubjectError::AttributeNotString);
    }
    let mut username = if width == 0 {
        selected.value
    } else {
        convert_openssl_wide_string(&selected.value, width as usize)?
    };
    if let Some(index) = username.iter().position(|byte| *byte == 0) {
        username.truncate(index);
    }
    username.truncate(CERTIFICATE_USERNAME_LENGTH.min(username.len()));
    for byte in &mut username {
        if *byte < 0x20 || *byte == 0x7f {
            *byte = b'_';
        }
    }
    Ok(String::from_utf8_lossy(&username).into_owned())
}

pub fn certificate_common_name(
    raw_subject: &[u8],
) -> Result<String, CertificateSubjectError> {
    certificate_username(raw_subject, "2.5.4.3")
}

fn parse_distinguished_name(
    raw: &[u8],
) -> Result<Vec<Vec<DistinguishedNameAttribute>>, CertificateSubjectError> {
    let (tag, sequence, remaining) = read_tlv(raw)?;
    if tag != 0x30 || !remaining.is_empty() {
        return Err(CertificateSubjectError::MalformedName);
    }
    let mut relative_names = Vec::new();
    let mut sequence = sequence;
    while !sequence.is_empty() {
        let (tag, set, remaining) = read_tlv(sequence)?;
        if tag != 0x31 {
            return Err(CertificateSubjectError::MalformedRelativeName);
        }
        sequence = remaining;
        let mut attributes = Vec::new();
        let mut set = set;
        while !set.is_empty() {
            let (tag, attribute, remaining) = read_tlv(set)?;
            if tag != 0x30 {
                return Err(CertificateSubjectError::MalformedAttribute);
            }
            set = remaining;
            let (oid_tag, oid, attribute_remaining) = read_tlv(attribute)?;
            if oid_tag != 0x06 {
                return Err(CertificateSubjectError::MalformedAttribute);
            }
            let (value_tag, value, trailing) = read_tlv(attribute_remaining)?;
            if !trailing.is_empty() {
                return Err(CertificateSubjectError::MalformedAttribute);
            }
            attributes.push(DistinguishedNameAttribute {
                oid: decode_oid(oid)?,
                tag: value_tag,
                value: value.to_vec(),
            });
        }
        relative_names.push(attributes);
    }
    Ok(relative_names)
}

fn read_tlv(
    input: &[u8],
) -> Result<(u8, &[u8], &[u8]), CertificateSubjectError> {
    if input.len() < 2 {
        return Err(CertificateSubjectError::MalformedDer);
    }
    let tag = input[0];
    let (length, header) = if input[1] & 0x80 == 0 {
        (usize::from(input[1]), 2)
    } else {
        let count = usize::from(input[1] & 0x7f);
        if count == 0
            || count > std::mem::size_of::<usize>()
            || input.len() < 2 + count
        {
            return Err(CertificateSubjectError::MalformedDer);
        }
        let mut length = 0_usize;
        for byte in &input[2..2 + count] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(CertificateSubjectError::MalformedDer)?;
        }
        (length, 2 + count)
    };
    let end = header
        .checked_add(length)
        .filter(|end| *end <= input.len())
        .ok_or(CertificateSubjectError::MalformedDer)?;
    Ok((tag, &input[header..end], &input[end..]))
}

fn decode_oid(value: &[u8]) -> Result<String, CertificateSubjectError> {
    if value.is_empty() {
        return Err(CertificateSubjectError::MalformedOid);
    }
    let mut components = Vec::new();
    let mut component = 0_u64;
    let mut continued = false;
    for byte in value {
        component = component
            .checked_mul(128)
            .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
            .ok_or(CertificateSubjectError::MalformedOid)?;
        continued = byte & 0x80 != 0;
        if !continued {
            components.push(component);
            component = 0;
        }
    }
    if continued || components.is_empty() {
        return Err(CertificateSubjectError::MalformedOid);
    }
    let first = components.remove(0);
    let (head, second) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut oid = format!("{head}.{second}");
    for component in components {
        oid.push('.');
        oid.push_str(&component.to_string());
    }
    Ok(oid)
}

fn openssl_attribute_type_name(oid: &str) -> String {
    Asn1Object::from_str(oid)
        .ok()
        .and_then(|object| {
            (object.nid() != Nid::UNDEF)
                .then(|| object.nid().short_name().ok())
                .flatten()
        })
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| oid.chars().take(79).collect())
}

fn openssl_character_width(tag: u8) -> i8 {
    match tag {
        12 => 0, // UTF8String
        18 | 19 | 20 | 22 | 23 | 24 | 26 => 1,
        30 => 2, // BMPString
        28 => 4, // UniversalString
        _ => -1,
    }
}

fn print_attribute_value(
    tag: u8,
    value: &[u8],
) -> Result<Vec<u8>, CertificateSubjectError> {
    let width = openssl_character_width(tag);
    let converted = if width == 0 {
        value.to_vec()
    } else {
        convert_openssl_wide_string(value, width.max(1) as usize)?
    };
    Ok(escape_openssl_control_characters(&converted))
}

fn convert_openssl_wide_string(
    value: &[u8],
    width: usize,
) -> Result<Vec<u8>, CertificateSubjectError> {
    if width == 0 || !value.len().is_multiple_of(width) {
        return Err(CertificateSubjectError::MalformedAttributeValue);
    }
    let mut converted = Vec::with_capacity(value.len());
    for units in value.chunks_exact(width) {
        let mut character = 0_u32;
        for unit in units {
            character = (character << 8) | u32::from(*unit);
        }
        append_openssl_utf8(&mut converted, character);
    }
    Ok(converted)
}

fn append_openssl_utf8(destination: &mut Vec<u8>, character: u32) {
    match character {
        0..=0x7f => destination.push(character as u8),
        0x80..=0x7ff => destination.extend_from_slice(&[
            ((character >> 6) as u8 & 0x1f) | 0xc0,
            (character as u8 & 0x3f) | 0x80,
        ]),
        0x800..=0xffff => destination.extend_from_slice(&[
            ((character >> 12) as u8 & 0x0f) | 0xe0,
            ((character >> 6) as u8 & 0x3f) | 0x80,
            (character as u8 & 0x3f) | 0x80,
        ]),
        0x10000..=0x1fffff => destination.extend_from_slice(&[
            ((character >> 18) as u8 & 0x07) | 0xf0,
            ((character >> 12) as u8 & 0x3f) | 0x80,
            ((character >> 6) as u8 & 0x3f) | 0x80,
            (character as u8 & 0x3f) | 0x80,
        ]),
        0x200000..=0x3ffffff => destination.extend_from_slice(&[
            ((character >> 24) as u8 & 0x03) | 0xf8,
            ((character >> 18) as u8 & 0x3f) | 0x80,
            ((character >> 12) as u8 & 0x3f) | 0x80,
            ((character >> 6) as u8 & 0x3f) | 0x80,
            (character as u8 & 0x3f) | 0x80,
        ]),
        _ => destination.extend_from_slice(&[
            ((character >> 30) as u8 & 0x01) | 0xfc,
            ((character >> 24) as u8 & 0x3f) | 0x80,
            ((character >> 18) as u8 & 0x3f) | 0x80,
            ((character >> 12) as u8 & 0x3f) | 0x80,
            ((character >> 6) as u8 & 0x3f) | 0x80,
            (character as u8 & 0x3f) | 0x80,
        ]),
    }
}

fn escape_openssl_control_characters(value: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut escaped = Vec::with_capacity(value.len());
    for character in value {
        match *character {
            0x00..=0x1f | 0x7f => escaped.extend_from_slice(&[
                b'\\',
                HEX[usize::from(character >> 4)],
                HEX[usize::from(character & 0x0f)],
            ]),
            b'\\' => escaped.extend_from_slice(b"\\\\"),
            character => escaped.push(character),
        }
    }
    escaped
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertificateSubjectError {
    #[error("malformed certificate name DER")]
    MalformedDer,
    #[error("malformed certificate name")]
    MalformedName,
    #[error("malformed certificate relative name")]
    MalformedRelativeName,
    #[error("malformed certificate subject attribute")]
    MalformedAttribute,
    #[error("malformed certificate subject OID")]
    MalformedOid,
    #[error("empty certificate subject")]
    EmptySubject,
    #[error("certificate subject carries no {0} attribute")]
    MissingAttribute(String),
    #[error("certificate subject attribute is not a string")]
    AttributeNotString,
    #[error("malformed certificate name attribute value")]
    MalformedAttributeValue,
}

#[cfg(test)]
mod tests {
    use openssl::x509::{X509, X509NameBuilder};

    use super::*;

    #[test]
    fn formats_real_openssl_subject_and_extracts_last_common_name() {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("O", "Example\\Org").unwrap();
        name.append_entry_by_text("CN", "first").unwrap();
        name.append_entry_by_text("CN", "last\nname").unwrap();
        let name = name.build();
        let raw = name.to_der().unwrap();
        assert_eq!(
            format_certificate_subject(&raw).unwrap(),
            r"O=Example\\Org, CN=first, CN=last\0Aname"
        );
        assert_eq!(certificate_common_name(&raw).unwrap(), "last_name");
    }

    #[test]
    fn subject_helpers_accept_a_certificate_subject_der() {
        let cert =
            rcgen::generate_simple_self_signed(vec!["vpn.example".into()])
                .unwrap()
                .cert
                .pem();
        let cert = X509::from_pem(cert.as_bytes()).unwrap();
        let raw = cert.subject_name().to_der().unwrap();
        assert_eq!(
            certificate_common_name(&raw).unwrap(),
            "rcgen self signed cert"
        );
        assert!(
            format_certificate_subject(&raw)
                .unwrap()
                .contains("CN=rcgen self signed cert")
        );
    }

    #[test]
    fn supports_bmp_unknown_oid_and_username_truncation() {
        // SEQUENCE { SET { SEQUENCE { OID 1.2.3, BMPString "AΩ" } } }
        let raw = hex::decode("300e310c300a06022a031e04004103a9").unwrap();
        assert_eq!(format_certificate_subject(&raw).unwrap(), "1.2.3=AΩ");
        assert_eq!(certificate_username(&raw, "1.2.3").unwrap(), "AΩ");

        let mut long_name = vec![0x30, 0x5b, 0x31, 0x59, 0x30, 0x57];
        long_name.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 80]);
        long_name.extend_from_slice(&[b'a'; 80]);
        assert_eq!(certificate_common_name(&long_name).unwrap().len(), 64);
    }

    #[test]
    fn rejects_malformed_der_and_non_string_username() {
        assert!(format_certificate_subject(&[]).is_err());
        // CN whose value is an INTEGER.
        let raw = hex::decode("300c310a30080603550403020101").unwrap();
        assert_eq!(format_certificate_subject(&raw).unwrap(), "CN=\\01");
        assert_eq!(
            certificate_common_name(&raw).unwrap_err(),
            CertificateSubjectError::AttributeNotString
        );
    }
}
