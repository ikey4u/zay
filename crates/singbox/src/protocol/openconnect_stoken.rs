//! RSA SecurID CTF v1-v4 software-token support.
//!
//! The wire and derivation behavior follows libstoken commit
//! `837e843e8850d14a5d49d799b066d61d04fd649a` through the locked
//! `sing-openconnect` implementation. OpenConnect intentionally does not
//! enforce the provisioning expiry gate when computing a tokencode.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac13::{Hmac, Mac};
use openssl::{
    hash::MessageDigest,
    memcmp, pkcs5,
    symm::{Cipher, Crypter, Mode},
};
use sha2::Sha256;
use zeroize::Zeroize;

use super::{AnyConnectSoftwareTokenGenerator, OathTokenError};

const PASSWORD_PROTECTION: u16 = 1 << 13;
const DEVICE_PROTECTION: u16 = 1 << 12;
const TIME_DERIVED_SEEDS: u16 = 1 << 9;
const DIGIT_SHIFT: u16 = 6;
const DIGIT_MASK: u16 = 0x07 << DIGIT_SHIFT;
const PIN_MODE_SHIFT: u16 = 3;
const PIN_MODE_MASK: u16 = 0x03 << PIN_MODE_SHIFT;
const INTERVAL_MASK: u16 = 0x03;
const BIT_128: u16 = 1 << 14;
const V3_ADD_PIN_OFF: u8 = 0x1f;
const V3_KEY_0: [u8; 16] = [
    0xd0, 0x14, 0x43, 0x3c, 0x6d, 0x17, 0x9f, 0xeb, 0xda, 0x09, 0xab, 0xfc,
    0x32, 0x49, 0x63, 0x4c,
];
const V3_KEY_1: [u8; 16] = [
    0x3b, 0xaf, 0xff, 0x4d, 0x91, 0x8d, 0x89, 0xb6, 0x81, 0x60, 0xde, 0x44,
    0x4e, 0x05, 0xc0, 0xdd,
];
const V2_MAGIC: [u8; 6] = [0xd8, 0xf5, 0x32, 0x53, 0x82, 0x89];

#[derive(Clone)]
pub struct OpenConnectSecurIdTokenFactory {
    configuration: Arc<SecurIdConfiguration>,
}

impl OpenConnectSecurIdTokenFactory {
    pub fn new(
        secret: &str,
        pin: &str,
        password: &str,
        device_id: &str,
    ) -> Result<Self, OathTokenError> {
        let mut token = parse_token(secret)?;
        decrypt_token(&mut token, password, device_id)?;
        let uses_pin = ((token.flags & PIN_MODE_MASK) >> PIN_MODE_SHIFT) >= 2;
        if uses_pin {
            validate_pin(pin)?;
        }
        Ok(Self {
            configuration: Arc::new(SecurIdConfiguration {
                token,
                pin: pin.into(),
                uses_pin,
            }),
        })
    }

    pub fn generator(&self) -> OpenConnectSecurIdTokenGenerator {
        OpenConnectSecurIdTokenGenerator {
            configuration: self.configuration.clone(),
            attempts: 0,
            first_generation_time: 0,
        }
    }

    pub fn period(&self) -> u64 {
        self.configuration.token.period()
    }
}

struct SecurIdConfiguration {
    token: SecurIdToken,
    pin: String,
    uses_pin: bool,
}

impl Drop for SecurIdConfiguration {
    fn drop(&mut self) {
        self.pin.zeroize();
    }
}

pub struct OpenConnectSecurIdTokenGenerator {
    configuration: Arc<SecurIdConfiguration>,
    attempts: u8,
    first_generation_time: u64,
}

impl AnyConnectSoftwareTokenGenerator for OpenConnectSecurIdTokenGenerator {
    fn token_type(&self) -> &'static str {
        "stoken"
    }

    fn can_generate(&self, message: &str) -> bool {
        self.attempts == 0
            || (self.attempts == 1
                && message.to_ascii_lowercase().contains("next tokencode"))
    }

    fn generate(&mut self, message: &str) -> Result<String, OathTokenError> {
        if !self.can_generate(message) {
            return Err(OathTokenError::AttemptLimit);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OathTokenError::InvalidClock)?
            .as_secs();
        let generation_time = if self.attempts == 0 {
            self.first_generation_time = now;
            now
        } else {
            self.first_generation_time
                .checked_add(self.configuration.token.period())
                .ok_or(OathTokenError::TimeExhausted)?
        };
        let mut code = compute_token_code(
            &self.configuration.token,
            &self.configuration.pin,
            self.configuration.uses_pin,
            generation_time,
        )?;
        if !self.configuration.uses_pin {
            code.insert_str(0, &self.configuration.pin);
        }
        self.attempts += 1;
        Ok(code)
    }
}

struct SecurIdToken {
    version: u8,
    serial: String,
    flags: u16,
    smartphone: bool,
    encrypted_seed: [u8; 16],
    decrypted_seed: [u8; 16],
    decrypted_seed_hash: u16,
    device_id_hash: u16,
    v3: Option<Box<SecurIdV3Token>>,
}

impl SecurIdToken {
    fn period(&self) -> u64 {
        if self.flags & INTERVAL_MASK == 0 {
            30
        } else {
            60
        }
    }
}

impl Drop for SecurIdToken {
    fn drop(&mut self) {
        self.decrypted_seed.zeroize();
    }
}

struct SecurIdV3Token {
    version: u8,
    password_locked: u8,
    device_locked: u8,
    nonce_device_hash: [u8; 32],
    nonce_device_password_hash: [u8; 32],
    nonce: [u8; 16],
    encrypted_payload: [u8; 176],
    message_authentication_code: [u8; 32],
}

fn parse_token(secret: &str) -> Result<SecurIdToken, OathTokenError> {
    let trimmed = secret.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("<?xml") {
        return Err(sid(
            "SDTID/XML provisioning is not supported; provide an encoded CTF token string",
        ));
    }
    if trimmed.starts_with('@')
        || trimmed.starts_with('/')
        || lower.starts_with("version ")
        || lower.contains("\nversion ")
    {
        return Err(sid(
            "stoken rcfiles and token file paths are not supported; provide the encoded token contents",
        ));
    }
    let marker = find_ascii_case_insensitive(trimmed, "ctfData=3D")
        .map(|offset| (offset, 10))
        .or_else(|| {
            find_ascii_case_insensitive(trimmed, "ctfData=")
                .map(|offset| (offset, 8))
        });
    let mut token_text = marker
        .map(|(offset, length)| &trimmed[offset + length..])
        .unwrap_or(trimmed);
    if let Some(end) = token_text.find('&') {
        token_text = &token_text[..end];
    }
    let decoded = decode_percent_encoding(token_text.trim())?;
    let first = decoded
        .as_bytes()
        .first()
        .copied()
        .ok_or_else(|| sid("token string is empty"))?;
    let smartphone = lower.starts_with("com.rsa.securid.iphone://ctf")
        || lower.starts_with("com.rsa.securid://ctf")
        || lower.starts_with("http://127.0.0.1/securid/ctf");
    match first {
        b'1' | b'2' => parse_v2_token(&decoded, smartphone),
        b'A' | b'B' => parse_v3_token(&decoded),
        _ => Err(sid(
            "unsupported token format; supported CTF versions are 1, 2, 3, and 4",
        )),
    }
}

fn parse_v2_token(
    token_text: &str,
    smartphone: bool,
) -> Result<SecurIdToken, OathTokenError> {
    let mut numeric = Vec::with_capacity(token_text.len());
    for byte in token_text.bytes() {
        if byte.is_ascii_digit() {
            numeric.push(byte);
        } else if byte != b'-' {
            break;
        }
    }
    if !(81..=85).contains(&numeric.len()) {
        return Err(sid(format!(
            "invalid version 1/2 token length: {}",
            numeric.len()
        )));
    }
    let checksum_bits = decode_numeric_bits(&numeric[numeric.len() - 5..], 15)?;
    let provided_checksum = read_bits(&checksum_bits, 0, 15) as u16;
    let computed_checksum = compute_short_mac(&numeric[..numeric.len() - 5])?;
    if provided_checksum != computed_checksum {
        return Err(sid("version 1/2 token checksum verification failed"));
    }
    let payload = decode_numeric_bits(&numeric[13..76], 189)?;
    let mut encrypted_seed = [0; 16];
    encrypted_seed.copy_from_slice(&payload[..16]);
    Ok(SecurIdToken {
        version: numeric[0] - b'0',
        serial: String::from_utf8(numeric[1..13].to_vec())
            .expect("numeric serial is ASCII"),
        flags: read_bits(&payload, 128, 16) as u16,
        smartphone,
        encrypted_seed,
        decrypted_seed: [0; 16],
        decrypted_seed_hash: read_bits(&payload, 159, 15) as u16,
        device_id_hash: read_bits(&payload, 174, 15) as u16,
        v3: None,
    })
}

fn parse_v3_token(token_text: &str) -> Result<SecurIdToken, OathTokenError> {
    let decoded = STANDARD
        .decode(token_text)
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(token_text)
        })
        .map_err(|error| sid(format!("decode version 3/4 token: {error}")))?;
    if decoded.len() != 291 {
        return Err(sid(format!(
            "invalid version 3/4 token length: {}",
            decoded.len()
        )));
    }
    if !matches!(decoded[0], 3 | 4) {
        return Err(sid(format!("unsupported CTF version: {}", decoded[0])));
    }
    let mut nonce_device_hash = [0; 32];
    nonce_device_hash.copy_from_slice(&decoded[3..35]);
    let mut nonce_device_password_hash = [0; 32];
    nonce_device_password_hash.copy_from_slice(&decoded[35..67]);
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&decoded[67..83]);
    let mut encrypted_payload = [0; 176];
    encrypted_payload.copy_from_slice(&decoded[83..259]);
    let mut message_authentication_code = [0; 32];
    message_authentication_code.copy_from_slice(&decoded[259..291]);
    let v3 = SecurIdV3Token {
        version: decoded[0],
        password_locked: decoded[1],
        device_locked: decoded[2],
        nonce_device_hash,
        nonce_device_password_hash,
        nonce,
        encrypted_payload,
        message_authentication_code,
    };
    let mut flags = 0;
    if v3.password_locked != 0 {
        flags |= PASSWORD_PROTECTION;
    }
    if v3.device_locked != 0 {
        flags |= DEVICE_PROTECTION;
    }
    Ok(SecurIdToken {
        version: v3.version,
        serial: String::new(),
        flags,
        smartphone: false,
        encrypted_seed: [0; 16],
        decrypted_seed: [0; 16],
        decrypted_seed_hash: 0,
        device_id_hash: 0,
        v3: Some(Box::new(v3)),
    })
}

fn decrypt_token(
    token: &mut SecurIdToken,
    password: &str,
    device_id: &str,
) -> Result<(), OathTokenError> {
    let password = if token.flags & PASSWORD_PROTECTION != 0 {
        if password.is_empty() {
            return Err(sid("token requires a password"));
        }
        if password.len() > 40 {
            return Err(sid("token password exceeds 40 bytes"));
        }
        password
    } else {
        ""
    };
    let device_id = if token.flags & DEVICE_PROTECTION != 0 {
        if device_id.is_empty() {
            return Err(sid("token requires a device ID"));
        }
        device_id
    } else {
        ""
    };
    if token.v3.is_some() {
        decrypt_v3_token(token, password, device_id)
    } else {
        decrypt_v2_token(token, password, device_id)
    }
}

fn decrypt_v2_token(
    token: &mut SecurIdToken,
    password: &str,
    device_id: &str,
) -> Result<(), OathTokenError> {
    let (key, device_hash) = generate_v2_key_hash(token, password, device_id)?;
    if token.flags & DEVICE_PROTECTION != 0
        && device_hash != token.device_id_hash
    {
        return Err(sid("token device ID verification failed"));
    }
    token.decrypted_seed = aes_decrypt_block(&key, &token.encrypted_seed)?;
    if compute_short_mac(&token.decrypted_seed)? != token.decrypted_seed_hash {
        return Err(sid("token password or device ID verification failed"));
    }
    Ok(())
}

fn generate_v2_key_hash(
    token: &SecurIdToken,
    password: &str,
    device_id: &str,
) -> Result<([u8; 16], u16), OathTokenError> {
    let device_id_length = if token.smartphone { 40 } else { 32 };
    let mut material = [0_u8; 87];
    material[..password.len()].copy_from_slice(password.as_bytes());
    let mut position = password.len();
    let device_id_start = position;
    for (consumed, byte) in device_id.bytes().enumerate() {
        if consumed >= device_id_length {
            break;
        }
        let accepted = if token.version == 1 {
            !byte.is_ascii_digit()
        } else {
            byte.is_ascii_hexdigit()
        };
        if accepted {
            material[position] = byte.to_ascii_uppercase();
            position += 1;
        }
    }
    let device_hash = compute_short_mac(
        &material[device_id_start..device_id_start + device_id_length],
    )?;
    material[position..position + V2_MAGIC.len()].copy_from_slice(&V2_MAGIC);
    Ok((
        compute_mac(&material[..position + V2_MAGIC.len()])?,
        device_hash,
    ))
}

fn decrypt_v3_token(
    token: &mut SecurIdToken,
    password: &str,
    raw_device_id: &str,
) -> Result<(), OathTokenError> {
    let v3 = token.v3.as_ref().expect("checked by caller");
    let device_id = scrub_v3_device_id(raw_device_id);
    if !memcmp::eq(
        &compute_v3_hash("", &device_id, &v3.nonce),
        &v3.nonce_device_hash,
    ) {
        return Err(sid("token device ID verification failed"));
    }
    if !memcmp::eq(
        &compute_v3_hash(password, &device_id, &v3.nonce),
        &v3.nonce_device_password_hash,
    ) {
        return Err(sid("token password verification failed"));
    }
    let authentication_key =
        derive_v3_key(password, &device_id, &v3.nonce, &V3_KEY_0, v3.version)?;
    let mut mac =
        <Hmac<Sha256> as hmac13::KeyInit>::new_from_slice(&authentication_key)
            .map_err(|error| {
                sid(format!("initialize version 3/4 HMAC: {error}"))
            })?;
    let serialized = serialize_v3_token(v3);
    mac.update(&serialized[..259]);
    if !memcmp::eq(
        &mac.finalize().into_bytes(),
        &v3.message_authentication_code,
    ) {
        return Err(sid("version 3/4 token integrity verification failed"));
    }
    let decryption_key =
        derive_v3_key(password, &device_id, &v3.nonce, &V3_KEY_1, v3.version)?;
    let payload =
        aes_256_cbc_decrypt(&decryption_key, &v3.nonce, &v3.encrypted_payload)?;
    if payload[12] != 0
        || payload[..12].contains(&0)
        || !payload[..12].iter().all(u8::is_ascii_digit)
    {
        return Err(sid("invalid version 3/4 serial number"));
    }
    if !(1..=8).contains(&payload[35]) {
        return Err(sid(format!(
            "invalid version 3/4 tokencode digit count: {}",
            payload[35]
        )));
    }
    token.serial = String::from_utf8(payload[..12].to_vec())
        .expect("validated serial is ASCII");
    token.decrypted_seed.copy_from_slice(&payload[16..32]);
    token.flags |= TIME_DERIVED_SEEDS | BIT_128;
    token.flags |= u16::from(payload[35] - 1) << DIGIT_SHIFT;
    if payload[36] != V3_ADD_PIN_OFF {
        token.flags |= 2 << PIN_MODE_SHIFT;
    }
    if payload[37] == 60 {
        token.flags |= 1;
    }
    Ok(())
}

fn compute_v3_hash(
    password: &str,
    device_id: &str,
    nonce: &[u8; 16],
) -> [u8; 32] {
    use sha2::Digest as _;
    let mut input = vec![0; 16 + 48 + password.len()];
    input[..16].copy_from_slice(nonce);
    input[16..16 + device_id.len()].copy_from_slice(device_id.as_bytes());
    input[64..].copy_from_slice(password.as_bytes());
    Sha256::digest(input).into()
}

fn derive_v3_key(
    password: &str,
    device_id: &str,
    nonce: &[u8; 16],
    key_id: &[u8; 16],
    version: u8,
) -> Result<[u8; 32], OathTokenError> {
    let mut input = vec![0; 80 + password.len()];
    input[..password.len()].copy_from_slice(password.as_bytes());
    let device_start = password.len();
    input[device_start..device_start + device_id.len()]
        .copy_from_slice(device_id.as_bytes());
    let key_start = password.len() + 48;
    input[key_start..key_start + 16].copy_from_slice(key_id);
    input[key_start + 16..].copy_from_slice(nonce);
    if version == 3 {
        input = input.iter().skip(1).step_by(2).copied().collect();
    }
    let mut output = [0; 32];
    pkcs5::pbkdf2_hmac(
        &input,
        nonce,
        1000,
        MessageDigest::sha256(),
        &mut output,
    )
    .map_err(|error| sid(format!("derive version 3/4 key: {error}")))?;
    input.zeroize();
    Ok(output)
}

fn serialize_v3_token(token: &SecurIdV3Token) -> [u8; 291] {
    let mut serialized = [0; 291];
    serialized[0] = token.version;
    serialized[1] = token.password_locked;
    serialized[2] = token.device_locked;
    serialized[3..35].copy_from_slice(&token.nonce_device_hash);
    serialized[35..67].copy_from_slice(&token.nonce_device_password_hash);
    serialized[67..83].copy_from_slice(&token.nonce);
    serialized[83..259].copy_from_slice(&token.encrypted_payload);
    serialized[259..].copy_from_slice(&token.message_authentication_code);
    serialized
}

fn scrub_v3_device_id(device_id: &str) -> String {
    device_id
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .take(48)
        .map(|byte| byte.to_ascii_uppercase() as char)
        .collect()
}

fn compute_token_code(
    token: &SecurIdToken,
    pin: &str,
    apply_pin: bool,
    unix_time: u64,
) -> Result<String, OathTokenError> {
    let datetime = time::OffsetDateTime::from_unix_timestamp(
        i64::try_from(unix_time).map_err(|_| OathTokenError::TimeExhausted)?,
    )
    .map_err(|_| OathTokenError::TimeExhausted)?;
    let mut bcd_time = [0; 8];
    write_bcd(&mut bcd_time[..2], datetime.year());
    write_bcd(&mut bcd_time[2..3], u8::from(datetime.month()) as i32);
    write_bcd(&mut bcd_time[3..4], datetime.day() as i32);
    write_bcd(&mut bcd_time[4..5], datetime.hour() as i32);
    let interval = token.period();
    let minute_mask = if interval == 30 { 1 } else { 3 };
    write_bcd(
        &mut bcd_time[5..6],
        i32::from(datetime.minute() & !minute_mask),
    );
    let mut key0 = build_time_key(&bcd_time[..2], &token.serial)?;
    key0 = aes_encrypt_block(&token.decrypted_seed, &key0)?;
    let mut key1 = build_time_key(&bcd_time[..3], &token.serial)?;
    key1 = aes_encrypt_block(&key0, &key1)?;
    key0 = build_time_key(&bcd_time[..4], &token.serial)?;
    key0 = aes_encrypt_block(&key1, &key0)?;
    key1 = build_time_key(&bcd_time[..5], &token.serial)?;
    key1 = aes_encrypt_block(&key0, &key1)?;
    key0 = build_time_key(&bcd_time, &token.serial)?;
    key0 = aes_encrypt_block(&key1, &key0)?;
    let offset = if interval == 30 {
        usize::from(
            ((datetime.minute() & 1) << 3)
                | (u8::from(datetime.second() >= 30) << 2),
        )
    } else {
        usize::from((datetime.minute() & 3) << 2)
    };
    let mut value = u32::from_be_bytes(
        key0[offset..offset + 4]
            .try_into()
            .expect("SecurID offset is block aligned"),
    );
    let digits = usize::from(((token.flags & DIGIT_MASK) >> DIGIT_SHIFT) + 1);
    let mut code = vec![b'0'; digits];
    for index in (0..digits).rev() {
        let mut digit = (value % 10) as u8;
        value /= 10;
        let pin_offset = digits - 1 - index;
        if apply_pin && pin_offset < pin.len() {
            digit += pin.as_bytes()[pin.len() - 1 - pin_offset] - b'0';
        }
        code[index] = digit % 10 + b'0';
    }
    Ok(String::from_utf8(code).expect("tokencode is ASCII"))
}

fn build_time_key(
    time: &[u8],
    serial: &str,
) -> Result<[u8; 16], OathTokenError> {
    if serial.len() != 12 || !serial.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(sid("invalid token serial number"));
    }
    let serial = serial.as_bytes();
    let mut key = [0; 16];
    key[..8].fill(0xaa);
    key[..time.len()].copy_from_slice(time);
    key[12..].fill(0xbb);
    for index in (4..12).step_by(2) {
        key[8 + (index - 4) / 2] =
            (serial[index] - b'0') << 4 | (serial[index + 1] - b'0');
    }
    Ok(key)
}

fn write_bcd(destination: &mut [u8], mut value: i32) {
    for byte in destination.iter_mut().rev() {
        *byte = (value % 10) as u8;
        value /= 10;
        *byte |= ((value % 10) as u8) << 4;
        value /= 10;
    }
}

fn compute_short_mac(input: &[u8]) -> Result<u16, OathTokenError> {
    let mac = compute_mac(input)?;
    Ok(u16::from(mac[0]) << 7 | u16::from(mac[1]) >> 1)
}

fn compute_mac(input: &[u8]) -> Result<[u8; 16], OathTokenError> {
    let mut work = [0xff; 16];
    let mut padding = [0; 16];
    let mut bit_length = input.len() * 8;
    for byte in padding.iter_mut().rev() {
        if bit_length == 0 {
            break;
        }
        *byte = bit_length as u8;
        bit_length >>= 8;
    }
    let mut remaining = input;
    let mut odd = false;
    while remaining.len() > 16 {
        encrypt_then_xor(&remaining[..16], &mut work)?;
        remaining = &remaining[16..];
        odd = !odd;
    }
    let mut last = [0; 16];
    last[..remaining.len()].copy_from_slice(remaining);
    encrypt_then_xor(&last, &mut work)?;
    if odd {
        encrypt_then_xor(&[0; 16], &mut work)?;
    }
    encrypt_then_xor(&padding, &mut work)?;
    let mut result = work;
    encrypt_then_xor(&work, &mut result)?;
    Ok(result)
}

fn encrypt_then_xor(
    key: &[u8],
    work: &mut [u8; 16],
) -> Result<(), OathTokenError> {
    let encrypted = aes_encrypt_block(key, work)?;
    for (byte, encrypted) in work.iter_mut().zip(encrypted) {
        *byte ^= encrypted;
    }
    Ok(())
}

fn aes_encrypt_block(
    key: &[u8],
    input: &[u8],
) -> Result<[u8; 16], OathTokenError> {
    crypt_block(Cipher::aes_128_ecb(), Mode::Encrypt, key, input)
}

fn aes_decrypt_block(
    key: &[u8],
    input: &[u8],
) -> Result<[u8; 16], OathTokenError> {
    crypt_block(Cipher::aes_128_ecb(), Mode::Decrypt, key, input)
}

fn crypt_block(
    cipher: Cipher,
    mode: Mode,
    key: &[u8],
    input: &[u8],
) -> Result<[u8; 16], OathTokenError> {
    let mut crypter = Crypter::new(cipher, mode, key, None)
        .map_err(|error| sid(format!("initialize AES cipher: {error}")))?;
    crypter.pad(false);
    let mut output = [0; 32];
    let count = crypter
        .update(input, &mut output)
        .map_err(|error| sid(format!("execute AES cipher: {error}")))?;
    let final_count = crypter
        .finalize(&mut output[count..])
        .map_err(|error| sid(format!("finalize AES cipher: {error}")))?;
    if count + final_count != 16 {
        return Err(sid("AES block cipher returned an invalid length"));
    }
    Ok(output[..16].try_into().expect("checked AES block length"))
}

fn aes_256_cbc_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    input: &[u8; 176],
) -> Result<[u8; 176], OathTokenError> {
    let mut crypter =
        Crypter::new(Cipher::aes_256_cbc(), Mode::Decrypt, key, Some(nonce))
            .map_err(|error| {
                sid(format!("initialize payload cipher: {error}"))
            })?;
    crypter.pad(false);
    let mut output = [0; 192];
    let count = crypter
        .update(input, &mut output)
        .map_err(|error| sid(format!("decrypt payload: {error}")))?;
    let final_count =
        crypter.finalize(&mut output[count..]).map_err(|error| {
            sid(format!("finalize payload decryption: {error}"))
        })?;
    if count + final_count != 176 {
        return Err(sid("payload cipher returned an invalid length"));
    }
    Ok(output[..176].try_into().expect("checked payload length"))
}

fn decode_numeric_bits(
    input: &[u8],
    bit_count: usize,
) -> Result<Vec<u8>, OathTokenError> {
    if input.len() * 3 < bit_count {
        return Err(sid(format!(
            "numeric token does not contain {bit_count} bits"
        )));
    }
    let mut output = vec![0; bit_count.div_ceil(8)];
    for bit_position in 0..bit_count {
        let digit = input[bit_position / 3];
        if !digit.is_ascii_digit() {
            return Err(sid("invalid character in numeric token"));
        }
        let value = (digit - b'0') & 0x07;
        let value_bit = 2 - bit_position % 3;
        if value & (1 << value_bit) != 0 {
            output[bit_position / 8] |= 1 << (7 - bit_position % 8);
        }
    }
    Ok(output)
}

fn read_bits(input: &[u8], start: usize, bit_count: usize) -> u32 {
    let mut value = 0;
    for bit_position in start..start + bit_count {
        value <<= 1;
        if input[bit_position / 8] & (1 << (7 - bit_position % 8)) != 0 {
            value |= 1;
        }
    }
    value
}

fn decode_percent_encoding(input: &str) -> Result<String, OathTokenError> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || !bytes[index + 1].is_ascii_hexdigit()
            || !bytes[index + 2].is_ascii_hexdigit()
        {
            return Err(sid("invalid percent encoding in token"));
        }
        decoded.push(
            hex_nibble(bytes[index + 1]) << 4 | hex_nibble(bytes[index + 2]),
        );
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|error| sid(format!("token is not UTF-8: {error}")))
}

fn find_ascii_case_insensitive(value: &str, needle: &str) -> Option<usize> {
    value
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("validated hex digit"),
    }
}

fn validate_pin(pin: &str) -> Result<(), OathTokenError> {
    if !(4..=8).contains(&pin.len())
        || !pin.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(sid("token PIN must contain 4 to 8 digits"));
    }
    Ok(())
}

fn sid(message: impl Into<String>) -> OathTokenError {
    OathTokenError::SecurId(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_bit_decoder_matches_ctf_three_bit_digits() {
        assert_eq!(
            decode_numeric_bits(b"76543210", 24).unwrap(),
            vec![0xfa, 0xc6, 0x88]
        );
        assert!(decode_numeric_bits(b"12x", 9).is_err());
    }

    #[test]
    fn percent_encoding_and_device_scrubbing_match_stoken() {
        assert_eq!(decode_percent_encoding("A%2BB%2FC%3D").unwrap(), "A+B/C=");
        assert_eq!(scrub_v3_device_id("ab:cd-12_!?z"), "ABCD12Z");
        assert!(decode_percent_encoding("A%2").is_err());
    }

    #[test]
    fn stoken_retry_requires_next_tokencode_challenge() {
        let configuration = Arc::new(SecurIdConfiguration {
            token: SecurIdToken {
                version: 4,
                serial: "123456789012".into(),
                flags: 5 << DIGIT_SHIFT,
                smartphone: false,
                encrypted_seed: [0; 16],
                decrypted_seed: [0x11; 16],
                decrypted_seed_hash: 0,
                device_id_hash: 0,
                v3: None,
            },
            pin: String::new(),
            uses_pin: false,
        });
        let mut generator = OpenConnectSecurIdTokenGenerator {
            configuration,
            attempts: 0,
            first_generation_time: 0,
        };
        assert!(generator.can_generate(""));
        generator.generate("").unwrap();
        assert!(!generator.can_generate("try again"));
        assert!(generator.can_generate("Please enter NEXT TOKENCODE"));
    }

    #[test]
    fn fixed_go_v4_ctf_vector_decrypts_and_generates_tokencode() {
        // Generated by the locked sing-openconnect token_stoken.go using a
        // deterministic v4 payload, then fixed here as an independent oracle.
        let token = "BAEBW2CE5WDdYmYSdDuljr85OLHBqUvp8uj6dNTeQ4txCBRWNw68M3FW801DUpB1N1bG2+pfGxz6lU3iHQLebXUmYQABAgMEBQYHCAkKCwwNDg83LWnilwiUlw5Pd/l1qu+J7ptv5A7ddTKmGt5icHbxt7vWom0F1dpatNz+Ajs3Dhr3kVQD1IlzCaxnY1xA7mrQaEnukbIiYJX45PuyXgbjgULNxq+w0LeI5iVVro9j7vDZQwYQ7J0PHiMzeBQ/WEl1xuZjBew7jfyPzJTIGhor+Sepud5P+/Ny/ZKjNkxgEph9hWzvqfCgGlXIDB5lSAHGB9mHijz5548AUTGsTrch57/IzvuYr3Wuiv4Lu/lsvq8SfuVa4xlncPclrEeSr6eq";
        let factory = OpenConnectSecurIdTokenFactory::new(
            token,
            "2468",
            "s3cret",
            "ab:cd-12_!?z",
        )
        .unwrap();
        assert_eq!(factory.period(), 30);
        assert_eq!(
            compute_token_code(
                &factory.configuration.token,
                "2468",
                true,
                1_700_000_000,
            )
            .unwrap(),
            "83390903"
        );
        assert_eq!(compute_short_mac(b"SecurID oracle").unwrap(), 0x4911);
        assert_eq!(
            hex::encode(compute_mac(b"SecurID oracle").unwrap()),
            "92234481b7e6d33e7ce15413ebfce5a1"
        );
        assert!(
            OpenConnectSecurIdTokenFactory::new(
                token,
                "2468",
                "wrong",
                "ab:cd-12_!?z",
            )
            .is_err()
        );
        assert!(
            OpenConnectSecurIdTokenFactory::new(
                token,
                "2468",
                "s3cret",
                "wrong-device",
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_go_v2_ctf_vector_decrypts_and_generates_tokencode() {
        let token = "212345678901271461355045720430250524436233004127023153623072000000267516161136423";
        let factory = OpenConnectSecurIdTokenFactory::new(
            token,
            "1357",
            "pw",
            "a1b2c3d4e5f60718",
        )
        .unwrap();
        assert_eq!(factory.period(), 30);
        assert_eq!(
            compute_token_code(
                &factory.configuration.token,
                "1357",
                true,
                1_700_000_000,
            )
            .unwrap(),
            "03537409"
        );
        assert!(
            OpenConnectSecurIdTokenFactory::new(
                token,
                "1357",
                "wrong",
                "a1b2c3d4e5f60718",
            )
            .is_err()
        );
    }
}
