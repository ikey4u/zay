use alloc::vec::Vec;

use super::codec::{Codec, Reader};

/// Zero-copy parsed view of a ClientHello body (without the four-byte
/// handshake header). Server-side ECH needs exact wire bytes for HPKE AAD and
/// ClientHelloInner reconstruction.
pub(crate) struct RawClientHello<'a> {
    pub(crate) version_and_random: &'a [u8],
    pub(crate) session_id: &'a [u8],
    pub(crate) cipher_suites: &'a [u8],
    pub(crate) compression: &'a [u8],
    pub(crate) extensions: &'a [u8],
    pub(crate) extensions_offset: usize,
    pub(crate) trailing: &'a [u8],
}

impl<'a> RawClientHello<'a> {
    pub(crate) fn parse(body: &'a [u8]) -> Option<Self> {
        let mut reader = Reader::init(body);
        let version_and_random = reader.take(2 + 32)?;
        let session_id_len = u8::read(&mut reader).ok()? as usize;
        let session_id = reader.take(session_id_len)?;
        let cipher_suites_len = u16::read(&mut reader).ok()? as usize;
        let cipher_suites = reader.take(cipher_suites_len)?;
        let compression_len = u8::read(&mut reader).ok()? as usize;
        let compression = reader.take(compression_len)?;
        let extensions_len = u16::read(&mut reader).ok()? as usize;
        let extensions_offset = body.len() - reader.left();
        let extensions = reader.take(extensions_len)?;
        let trailing = reader.rest();
        Some(Self {
            version_and_random,
            session_id,
            cipher_suites,
            compression,
            extensions,
            extensions_offset,
            trailing,
        })
    }

    pub(crate) fn iter_extensions(&self) -> RawExtensionIter<'a> {
        RawExtensionIter {
            reader: Reader::init(self.extensions),
            total_len: self.extensions.len(),
        }
    }
}

pub(crate) struct RawExtensionIter<'a> {
    reader: Reader<'a>,
    total_len: usize,
}

impl<'a> RawExtensionIter<'a> {
    pub(crate) fn advance_to(
        &mut self,
        extension_type: u16,
    ) -> Result<RawExtension<'a>, ()> {
        loop {
            let extension = self.next().ok_or(())??;
            if extension.ext_type == extension_type {
                return Ok(extension);
            }
        }
    }
}

impl<'a> Iterator for RawExtensionIter<'a> {
    type Item = Result<RawExtension<'a>, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.reader.any_left() {
            return None;
        }
        let Ok(ext_type) = u16::read(&mut self.reader) else {
            return Some(Err(()));
        };
        let Ok(ext_len) = u16::read(&mut self.reader) else {
            return Some(Err(()));
        };
        let Some(data) = self.reader.take(ext_len as usize) else {
            return Some(Err(()));
        };
        let data_end = self.total_len - self.reader.left();
        Some(Ok(RawExtension {
            ext_type,
            data,
            data_end,
        }))
    }
}

pub(crate) struct RawExtension<'a> {
    pub(crate) ext_type: u16,
    pub(crate) data: &'a [u8],
    pub(crate) data_end: usize,
}

impl RawExtension<'_> {
    pub(crate) fn write_to(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.ext_type.to_be_bytes());
        output.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        output.extend_from_slice(self.data);
    }
}
