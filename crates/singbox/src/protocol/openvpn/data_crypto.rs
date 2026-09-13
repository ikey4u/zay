use hmac13::{Hmac, KeyInit, Mac};
use md5::Md5;
use ripemd::Ripemd160;
use sha1_11::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use super::OpenVpnDataCodecError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVpnAuthDigest {
    None,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Ripemd160,
}

impl OpenVpnAuthDigest {
    pub fn from_name(name: &str) -> Result<Self, OpenVpnDataCodecError> {
        match name {
            "NONE" => Ok(Self::None),
            "MD5" => Ok(Self::Md5),
            "" | "SHA1" => Ok(Self::Sha1),
            "SHA224" => Ok(Self::Sha224),
            "SHA256" => Ok(Self::Sha256),
            "SHA384" => Ok(Self::Sha384),
            "SHA512" => Ok(Self::Sha512),
            "RIPEMD160" => Ok(Self::Ripemd160),
            _ => Err(OpenVpnDataCodecError::UnsupportedAuth(name.to_owned())),
        }
    }

    pub fn output_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Md5 => 16,
            Self::Sha1 | Self::Ripemd160 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub(crate) fn sign(self, key: &[u8], payload: &[u8]) -> Vec<u8> {
        macro_rules! sign {
            ($digest:ty) => {{
                let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice(key)
                    .expect("HMAC accepts any key length");
                mac.update(payload);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Self::None => Vec::new(),
            Self::Md5 => sign!(Md5),
            Self::Sha1 => sign!(Sha1),
            Self::Sha224 => sign!(Sha224),
            Self::Sha256 => sign!(Sha256),
            Self::Sha384 => sign!(Sha384),
            Self::Sha512 => sign!(Sha512),
            Self::Ripemd160 => sign!(Ripemd160),
        }
    }

    pub(crate) fn verify(
        self,
        key: &[u8],
        payload: &[u8],
        expected: &[u8],
    ) -> bool {
        macro_rules! verify {
            ($digest:ty) => {{
                let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice(key)
                    .expect("HMAC accepts any key length");
                mac.update(payload);
                mac.verify_slice(expected).is_ok()
            }};
        }
        match self {
            Self::None => expected.is_empty(),
            Self::Md5 => verify!(Md5),
            Self::Sha1 => verify!(Sha1),
            Self::Sha224 => verify!(Sha224),
            Self::Sha256 => verify!(Sha256),
            Self::Sha384 => verify!(Sha384),
            Self::Sha512 => verify!(Sha512),
            Self::Ripemd160 => verify!(Ripemd160),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVpnCbcCipher {
    None,
    Blowfish,
    Des,
    TripleDesEde2,
    TripleDesEde3,
    Cast5,
    Aes128,
    Aes192,
    Aes256,
    Aria128,
    Aria192,
    Aria256,
    Camellia128,
    Camellia192,
    Camellia256,
    Seed,
    Sm4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVpnStreamMode {
    Cfb,
    Ofb,
}

impl OpenVpnCbcCipher {
    pub fn from_name(name: &str) -> Result<Self, OpenVpnDataCodecError> {
        match name {
            "NONE" => Ok(Self::None),
            "BF-CBC" => Ok(Self::Blowfish),
            "DES-CBC" => Ok(Self::Des),
            "DES-EDE-CBC" => Ok(Self::TripleDesEde2),
            "DES-EDE3-CBC" => Ok(Self::TripleDesEde3),
            "CAST5-CBC" => Ok(Self::Cast5),
            "AES-128-CBC" => Ok(Self::Aes128),
            "AES-192-CBC" => Ok(Self::Aes192),
            "AES-256-CBC" => Ok(Self::Aes256),
            "ARIA-128-CBC" => Ok(Self::Aria128),
            "ARIA-192-CBC" => Ok(Self::Aria192),
            "ARIA-256-CBC" => Ok(Self::Aria256),
            "CAMELLIA-128-CBC" => Ok(Self::Camellia128),
            "CAMELLIA-192-CBC" => Ok(Self::Camellia192),
            "CAMELLIA-256-CBC" => Ok(Self::Camellia256),
            "SEED-CBC" => Ok(Self::Seed),
            "SM4-CBC" => Ok(Self::Sm4),
            _ => Err(OpenVpnDataCodecError::UnsupportedCipher(name.to_owned())),
        }
    }

    pub fn key_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Des => 8,
            Self::Blowfish | Self::TripleDesEde2 | Self::Cast5 => 16,
            Self::Aes128
            | Self::Aria128
            | Self::Camellia128
            | Self::Seed
            | Self::Sm4 => 16,
            Self::TripleDesEde3
            | Self::Aes192
            | Self::Aria192
            | Self::Camellia192 => 24,
            Self::Aes256 | Self::Aria256 | Self::Camellia256 => 32,
        }
    }

    pub fn block_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Blowfish
            | Self::Des
            | Self::TripleDesEde2
            | Self::TripleDesEde3
            | Self::Cast5 => 8,
            _ => 16,
        }
    }

    pub(crate) fn encrypt(
        self,
        key_material: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

        macro_rules! encrypt {
            ($cipher:ty) => {
                cbc::Encryptor::<$cipher>::new_from_slices(
                    &key_material[..self.key_size()],
                    iv,
                )
                .map_err(|_| OpenVpnDataCodecError::InvalidKeyMaterial)?
                .encrypt_padded_vec::<Pkcs7>(plaintext)
            };
        }
        let output = match self {
            Self::None => plaintext.to_vec(),
            Self::Blowfish => encrypt!(blowfish::Blowfish),
            Self::Des => encrypt!(des::Des),
            Self::TripleDesEde2 => encrypt!(des::TdesEde2),
            Self::TripleDesEde3 => encrypt!(des::TdesEde3),
            Self::Cast5 => encrypt!(cast5::Cast5),
            Self::Aes128 => encrypt!(aes::Aes128),
            Self::Aes192 => encrypt!(aes::Aes192),
            Self::Aes256 => encrypt!(aes::Aes256),
            Self::Aria128 => encrypt!(aria::Aria128),
            Self::Aria192 => encrypt!(aria::Aria192),
            Self::Aria256 => encrypt!(aria::Aria256),
            Self::Camellia128 => encrypt!(camellia::Camellia128),
            Self::Camellia192 => encrypt!(camellia::Camellia192),
            Self::Camellia256 => encrypt!(camellia::Camellia256),
            Self::Seed => {
                use cbc01::cipher::{
                    BlockEncryptMut, KeyIvInit, block_padding::Pkcs7,
                };
                cbc01::Encryptor::<kisaseed::SEED>::new_from_slices(
                    &key_material[..16],
                    iv,
                )
                .map_err(|_| OpenVpnDataCodecError::InvalidKeyMaterial)?
                .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
            }
            Self::Sm4 => encrypt!(sm4::Sm4),
        };
        Ok(output)
    }

    pub(crate) fn decrypt(
        self,
        key_material: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};

        macro_rules! decrypt {
            ($cipher:ty) => {
                cbc::Decryptor::<$cipher>::new_from_slices(
                    &key_material[..self.key_size()],
                    iv,
                )
                .map_err(|_| OpenVpnDataCodecError::InvalidKeyMaterial)?
                .decrypt_padded_vec::<Pkcs7>(ciphertext)
                .map_err(|_| OpenVpnDataCodecError::InvalidPadding)?
            };
        }
        let output = match self {
            Self::None => ciphertext.to_vec(),
            Self::Blowfish => decrypt!(blowfish::Blowfish),
            Self::Des => decrypt!(des::Des),
            Self::TripleDesEde2 => decrypt!(des::TdesEde2),
            Self::TripleDesEde3 => decrypt!(des::TdesEde3),
            Self::Cast5 => decrypt!(cast5::Cast5),
            Self::Aes128 => decrypt!(aes::Aes128),
            Self::Aes192 => decrypt!(aes::Aes192),
            Self::Aes256 => decrypt!(aes::Aes256),
            Self::Aria128 => decrypt!(aria::Aria128),
            Self::Aria192 => decrypt!(aria::Aria192),
            Self::Aria256 => decrypt!(aria::Aria256),
            Self::Camellia128 => decrypt!(camellia::Camellia128),
            Self::Camellia192 => decrypt!(camellia::Camellia192),
            Self::Camellia256 => decrypt!(camellia::Camellia256),
            Self::Seed => {
                use cbc01::cipher::{
                    BlockDecryptMut, KeyIvInit, block_padding::Pkcs7,
                };
                cbc01::Decryptor::<kisaseed::SEED>::new_from_slices(
                    &key_material[..16],
                    iv,
                )
                .map_err(|_| OpenVpnDataCodecError::InvalidKeyMaterial)?
                .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .map_err(|_| OpenVpnDataCodecError::InvalidPadding)?
            }
            Self::Sm4 => decrypt!(sm4::Sm4),
        };
        Ok(output)
    }

    pub(crate) fn crypt_stream(
        self,
        mode: OpenVpnStreamMode,
        key_material: &[u8],
        iv: &[u8],
        payload: &[u8],
        encrypting: bool,
    ) -> Result<Vec<u8>, OpenVpnDataCodecError> {
        if self == Self::None {
            return Err(OpenVpnDataCodecError::UnsupportedCipher(
                "NONE stream mode".into(),
            ));
        }
        if self == Self::Seed {
            return crypt_seed_stream(
                mode,
                &key_material[..16],
                iv,
                payload,
                encrypting,
            );
        }
        match mode {
            OpenVpnStreamMode::Cfb => {
                use cfb_mode::cipher::KeyIvInit;
                macro_rules! crypt {
                    ($cipher:ty) => {{
                        let mut output = payload.to_vec();
                        if encrypting {
                            cfb_mode::Encryptor::<$cipher>::new_from_slices(
                                &key_material[..self.key_size()],
                                iv,
                            )
                            .map_err(|_| {
                                OpenVpnDataCodecError::InvalidKeyMaterial
                            })?
                            .encrypt(&mut output);
                        } else {
                            cfb_mode::Decryptor::<$cipher>::new_from_slices(
                                &key_material[..self.key_size()],
                                iv,
                            )
                            .map_err(|_| {
                                OpenVpnDataCodecError::InvalidKeyMaterial
                            })?
                            .decrypt(&mut output);
                        }
                        output
                    }};
                }
                Ok(match self {
                    Self::Blowfish => crypt!(blowfish::Blowfish),
                    Self::Des => crypt!(des::Des),
                    Self::TripleDesEde2 => crypt!(des::TdesEde2),
                    Self::TripleDesEde3 => crypt!(des::TdesEde3),
                    Self::Cast5 => crypt!(cast5::Cast5),
                    Self::Aes128 => crypt!(aes::Aes128),
                    Self::Aes192 => crypt!(aes::Aes192),
                    Self::Aes256 => crypt!(aes::Aes256),
                    Self::Aria128 => crypt!(aria::Aria128),
                    Self::Aria192 => crypt!(aria::Aria192),
                    Self::Aria256 => crypt!(aria::Aria256),
                    Self::Camellia128 => crypt!(camellia::Camellia128),
                    Self::Camellia192 => crypt!(camellia::Camellia192),
                    Self::Camellia256 => crypt!(camellia::Camellia256),
                    Self::Sm4 => crypt!(sm4::Sm4),
                    Self::None | Self::Seed => unreachable!(),
                })
            }
            OpenVpnStreamMode::Ofb => {
                use ofb::cipher::{InnerIvInit, KeyInit, StreamCipher};
                macro_rules! crypt {
                    ($cipher:ty) => {{
                        let mut output = payload.to_vec();
                        let block = <$cipher as KeyInit>::new_from_slice(
                            &key_material[..self.key_size()],
                        )
                        .map_err(|_| {
                            OpenVpnDataCodecError::InvalidKeyMaterial
                        })?;
                        let core =
                            ofb::OfbCore::<$cipher>::inner_iv_slice_init(
                                block, iv,
                            )
                            .map_err(|_| {
                                OpenVpnDataCodecError::InvalidKeyMaterial
                            })?;
                        let mut stream = ofb::Ofb::<$cipher>::from_core(core);
                        stream.apply_keystream(&mut output);
                        output
                    }};
                }
                Ok(match self {
                    Self::Blowfish => crypt!(blowfish::Blowfish),
                    Self::Des => crypt!(des::Des),
                    Self::TripleDesEde2 => crypt!(des::TdesEde2),
                    Self::TripleDesEde3 => crypt!(des::TdesEde3),
                    Self::Cast5 => crypt!(cast5::Cast5),
                    Self::Aes128 => crypt!(aes::Aes128),
                    Self::Aes192 => crypt!(aes::Aes192),
                    Self::Aes256 => crypt!(aes::Aes256),
                    Self::Aria128 => crypt!(aria::Aria128),
                    Self::Aria192 => crypt!(aria::Aria192),
                    Self::Aria256 => crypt!(aria::Aria256),
                    Self::Camellia128 => crypt!(camellia::Camellia128),
                    Self::Camellia192 => crypt!(camellia::Camellia192),
                    Self::Camellia256 => crypt!(camellia::Camellia256),
                    Self::Sm4 => crypt!(sm4::Sm4),
                    Self::None | Self::Seed => unreachable!(),
                })
            }
        }
    }
}

fn crypt_seed_stream(
    mode: OpenVpnStreamMode,
    key: &[u8],
    iv: &[u8],
    payload: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, OpenVpnDataCodecError> {
    match mode {
        OpenVpnStreamMode::Cfb => {
            use cfb08::cipher::{AsyncStreamCipher, KeyIvInit};
            let mut output = payload.to_vec();
            if encrypting {
                cfb08::Encryptor::<kisaseed::SEED>::new_from_slices(key, iv)
                    .map_err(|_| OpenVpnDataCodecError::InvalidKeyMaterial)?
                    .encrypt(&mut output);
            } else {
                cfb08::Decryptor::<kisaseed::SEED>::new_from_slices(key, iv)
                    .map_err(|_| OpenVpnDataCodecError::InvalidKeyMaterial)?
                    .decrypt(&mut output);
            }
            Ok(output)
        }
        OpenVpnStreamMode::Ofb => {
            use ofb06::cipher::{KeyIvInit, StreamCipher};
            let mut output = payload.to_vec();
            let mut stream =
                ofb06::Ofb::<kisaseed::SEED>::new_from_slices(key, iv)
                    .map_err(|_| OpenVpnDataCodecError::InvalidKeyMaterial)?;
            stream.apply_keystream(&mut output);
            Ok(output)
        }
    }
}

pub fn openvpn_stream_cipher_spec(
    name: &str,
) -> Result<(OpenVpnStreamMode, OpenVpnCbcCipher), OpenVpnDataCodecError> {
    let (base, mode) = if let Some(base) = name.strip_suffix("-CFB") {
        (base, OpenVpnStreamMode::Cfb)
    } else if let Some(base) = name.strip_suffix("-OFB") {
        (base, OpenVpnStreamMode::Ofb)
    } else {
        return Err(OpenVpnDataCodecError::UnsupportedCipher(name.to_owned()));
    };
    let cipher = OpenVpnCbcCipher::from_name(&format!("{base}-CBC"))?;
    if cipher == OpenVpnCbcCipher::None {
        return Err(OpenVpnDataCodecError::UnsupportedCipher(name.to_owned()));
    }
    Ok((mode, cipher))
}
