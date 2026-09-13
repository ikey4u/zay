//! SQLite-backed persistent DNS response cache.

use std::{
    io,
    net::IpAddr,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hickory_proto::{
    op::Message,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use rusqlite::{Connection, OptionalExtension as _, params};

use ipnet::IpNet;

pub struct PersistentDnsCache {
    connection: Mutex<Connection>,
    cache_id: String,
}

pub struct PersistentEntry {
    pub message: Message,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentRuleSetEntry {
    pub content: Vec<u8>,
    pub last_updated: SystemTime,
    pub etag: String,
    pub url_hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentFakeIpMetadata {
    pub inet4_range: Option<IpNet>,
    pub inet6_range: Option<IpNet>,
    pub current4: Option<IpAddr>,
    pub current6: Option<IpAddr>,
}

type FakeIpMetadataRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

impl std::fmt::Debug for PersistentDnsCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersistentDnsCache")
            .field("cache_id", &self.cache_id)
            .finish_non_exhaustive()
    }
}

impl PersistentDnsCache {
    pub fn open(
        path: impl AsRef<Path>,
        cache_id: impl Into<String>,
    ) -> io::Result<Self> {
        let connection = Connection::open(path).map_err(io::Error::other)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS dns_cache (
                    cache_id TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    qname TEXT NOT NULL,
                    qtype INTEGER NOT NULL,
                    client_subnet TEXT NOT NULL,
                    rewrite_ttl INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    message BLOB NOT NULL,
                    PRIMARY KEY (
                        cache_id, transport, qname, qtype,
                        client_subnet, rewrite_ttl
                    )
                 );
                 CREATE TABLE IF NOT EXISTS fakeip_cache (
                    cache_id TEXT NOT NULL,
                    address TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    is_ipv6 INTEGER NOT NULL,
                    PRIMARY KEY (cache_id, address),
                    UNIQUE (cache_id, domain, is_ipv6)
                 );
                 CREATE TABLE IF NOT EXISTS fakeip_metadata (
                    cache_id TEXT PRIMARY KEY,
                    inet4_range TEXT,
                    inet6_range TEXT,
                    current4 TEXT,
                    current6 TEXT
                 );
                 CREATE TABLE IF NOT EXISTS runtime_state (
                    cache_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (cache_id, kind, name)
                 );
                 CREATE TABLE IF NOT EXISTS rdrc_cache (
                    cache_id TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    qname TEXT NOT NULL,
                    qtype INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY (cache_id, transport, qname, qtype)
                 );
                 CREATE TABLE IF NOT EXISTS rule_set_cache (
                    cache_id TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    content BLOB NOT NULL,
                    last_updated INTEGER NOT NULL,
                    etag TEXT NOT NULL,
                    url_hash BLOB NOT NULL,
                    PRIMARY KEY (cache_id, tag)
                 );",
            )
            .map_err(io::Error::other)?;
        Ok(Self {
            connection: Mutex::new(connection),
            cache_id: cache_id.into(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load(
        &self,
        transport: &str,
        qname: &str,
        qtype: u16,
        client_subnet: Option<&str>,
        rewrite_ttl: Option<u32>,
    ) -> io::Result<Option<PersistentEntry>> {
        let connection = self.connection.lock().map_err(|_| {
            io::Error::other("persistent DNS cache mutex poisoned")
        })?;
        let row = connection
            .query_row(
                "SELECT expires_at, message FROM dns_cache
                 WHERE cache_id = ?1 AND transport = ?2 AND qname = ?3
                   AND qtype = ?4 AND client_subnet = ?5
                   AND rewrite_ttl = ?6",
                params![
                    self.cache_id,
                    transport,
                    qname,
                    qtype,
                    client_subnet.unwrap_or(""),
                    rewrite_ttl.map_or(-1_i64, i64::from),
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(io::Error::other)?;
        let Some((expires_at, bytes)) = row else {
            return Ok(None);
        };
        let seconds = u64::try_from(expires_at).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "persistent DNS cache has a negative expiry",
            )
        })?;
        let message = Message::read(&mut BinDecoder::new(&bytes))
            .map_err(io::Error::other)?;
        Ok(Some(PersistentEntry {
            message,
            expires_at: UNIX_EPOCH + Duration::from_secs(seconds),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save(
        &self,
        transport: &str,
        qname: &str,
        qtype: u16,
        client_subnet: Option<&str>,
        rewrite_ttl: Option<u32>,
        message: &Message,
        expires_at: SystemTime,
    ) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(512);
        message
            .emit(&mut BinEncoder::new(&mut bytes))
            .map_err(io::Error::other)?;
        let expires_at = expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        let expires_at = i64::try_from(expires_at).map_err(io::Error::other)?;
        self.connection
            .lock()
            .map_err(|_| {
                io::Error::other("persistent DNS cache mutex poisoned")
            })?
            .execute(
                "INSERT INTO dns_cache (
                    cache_id, transport, qname, qtype, client_subnet,
                    rewrite_ttl, expires_at, message
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (
                    cache_id, transport, qname, qtype,
                    client_subnet, rewrite_ttl
                 ) DO UPDATE SET expires_at = excluded.expires_at,
                                 message = excluded.message",
                params![
                    self.cache_id,
                    transport,
                    qname,
                    qtype,
                    client_subnet.unwrap_or(""),
                    rewrite_ttl.map_or(-1_i64, i64::from),
                    expires_at,
                    bytes,
                ],
            )
            .map_err(io::Error::other)?;
        Ok(())
    }

    pub fn clear(&self) -> io::Result<()> {
        self.connection
            .lock()
            .map_err(|_| {
                io::Error::other("persistent DNS cache mutex poisoned")
            })?
            .execute(
                "DELETE FROM dns_cache WHERE cache_id = ?1",
                params![self.cache_id],
            )
            .map_err(io::Error::other)?;
        Ok(())
    }

    pub fn load_fakeip_by_address(
        &self,
        address: IpAddr,
    ) -> io::Result<Option<String>> {
        self.connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .query_row(
                "SELECT domain FROM fakeip_cache
                 WHERE cache_id = ?1 AND address = ?2",
                params![self.cache_id, address.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(io::Error::other)
    }

    pub fn load_fakeip_by_domain(
        &self,
        domain: &str,
        ipv6: bool,
    ) -> io::Result<Option<IpAddr>> {
        let address: Option<String> = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .query_row(
                "SELECT address FROM fakeip_cache
                 WHERE cache_id = ?1 AND domain = ?2 AND is_ipv6 = ?3",
                params![self.cache_id, domain, i64::from(ipv6)],
                |row| row.get(0),
            )
            .optional()
            .map_err(io::Error::other)?;
        address
            .map(|address| address.parse().map_err(io::Error::other))
            .transpose()
    }

    pub fn save_fakeip(&self, address: IpAddr, domain: &str) -> io::Result<()> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?;
        let transaction = connection.transaction().map_err(io::Error::other)?;
        transaction
            .execute(
                "DELETE FROM fakeip_cache
                 WHERE cache_id = ?1
                   AND (address = ?2 OR (domain = ?3 AND is_ipv6 = ?4))",
                params![
                    self.cache_id,
                    address.to_string(),
                    domain,
                    i64::from(address.is_ipv6()),
                ],
            )
            .map_err(io::Error::other)?;
        transaction
            .execute(
                "INSERT INTO fakeip_cache
                    (cache_id, address, domain, is_ipv6)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    self.cache_id,
                    address.to_string(),
                    domain,
                    i64::from(address.is_ipv6()),
                ],
            )
            .map_err(io::Error::other)?;
        transaction.commit().map_err(io::Error::other)
    }

    pub fn load_fakeip_metadata(
        &self,
    ) -> io::Result<Option<PersistentFakeIpMetadata>> {
        let row: Option<FakeIpMetadataRow> = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .query_row(
                "SELECT inet4_range, inet6_range, current4, current6
                 FROM fakeip_metadata WHERE cache_id = ?1",
                params![self.cache_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(io::Error::other)?;
        let Some((inet4_range, inet6_range, current4, current6)) = row else {
            return Ok(None);
        };
        Ok(Some(PersistentFakeIpMetadata {
            inet4_range: parse_optional(inet4_range)?,
            inet6_range: parse_optional(inet6_range)?,
            current4: parse_optional(current4)?,
            current6: parse_optional(current6)?,
        }))
    }

    pub fn save_fakeip_metadata(
        &self,
        metadata: &PersistentFakeIpMetadata,
    ) -> io::Result<()> {
        self.connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .execute(
                "INSERT INTO fakeip_metadata (
                    cache_id, inet4_range, inet6_range, current4, current6
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (cache_id) DO UPDATE SET
                    inet4_range = excluded.inet4_range,
                    inet6_range = excluded.inet6_range,
                    current4 = excluded.current4,
                    current6 = excluded.current6",
                params![
                    self.cache_id,
                    display_optional(metadata.inet4_range),
                    display_optional(metadata.inet6_range),
                    display_optional(metadata.current4),
                    display_optional(metadata.current6),
                ],
            )
            .map_err(io::Error::other)?;
        Ok(())
    }

    pub fn clear_fakeip(&self) -> io::Result<()> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?;
        let transaction = connection.transaction().map_err(io::Error::other)?;
        transaction
            .execute(
                "DELETE FROM fakeip_cache WHERE cache_id = ?1",
                params![self.cache_id],
            )
            .map_err(io::Error::other)?;
        transaction
            .execute(
                "DELETE FROM fakeip_metadata WHERE cache_id = ?1",
                params![self.cache_id],
            )
            .map_err(io::Error::other)?;
        transaction.commit().map_err(io::Error::other)
    }

    pub fn load_selected(&self, group: &str) -> io::Result<Option<String>> {
        self.load_runtime_state("selected", group)
    }

    pub fn save_selected(&self, group: &str, selected: &str) -> io::Result<()> {
        self.save_runtime_state("selected", group, selected)
    }

    pub fn load_mode(&self) -> io::Result<Option<String>> {
        self.load_runtime_state("mode", "")
    }

    pub fn save_mode(&self, mode: &str) -> io::Result<()> {
        self.save_runtime_state("mode", "", mode)
    }

    pub fn load_group_expand(&self, group: &str) -> io::Result<Option<bool>> {
        self.load_runtime_state("group_expand", group)?
            .map(|value| match value.as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "persistent group expand state is not a boolean",
                )),
            })
            .transpose()
    }

    pub fn save_group_expand(
        &self,
        group: &str,
        expanded: bool,
    ) -> io::Result<()> {
        self.save_runtime_state(
            "group_expand",
            group,
            if expanded { "true" } else { "false" },
        )
    }

    pub fn load_rule_set(
        &self,
        tag: &str,
    ) -> io::Result<Option<PersistentRuleSetEntry>> {
        let row = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .query_row(
                "SELECT content, last_updated, etag, url_hash
                 FROM rule_set_cache
                 WHERE cache_id = ?1 AND tag = ?2",
                params![self.cache_id, tag],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(io::Error::other)?;
        let Some((content, last_updated, etag, url_hash)) = row else {
            return Ok(None);
        };
        let last_updated = u64::try_from(last_updated).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "persistent rule-set cache has a negative timestamp",
            )
        })?;
        Ok(Some(PersistentRuleSetEntry {
            content,
            last_updated: UNIX_EPOCH + Duration::from_secs(last_updated),
            etag,
            url_hash,
        }))
    }

    pub fn save_rule_set(
        &self,
        tag: &str,
        entry: &PersistentRuleSetEntry,
    ) -> io::Result<()> {
        let last_updated = entry
            .last_updated
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        let last_updated =
            i64::try_from(last_updated).map_err(io::Error::other)?;
        self.connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .execute(
                "INSERT INTO rule_set_cache (
                    cache_id, tag, content, last_updated, etag, url_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (cache_id, tag) DO UPDATE SET
                    content = excluded.content,
                    last_updated = excluded.last_updated,
                    etag = excluded.etag,
                    url_hash = excluded.url_hash",
                params![
                    self.cache_id,
                    tag,
                    entry.content,
                    last_updated,
                    entry.etag,
                    entry.url_hash,
                ],
            )
            .map_err(io::Error::other)?;
        Ok(())
    }

    pub fn load_rdrc(
        &self,
        transport: &str,
        qname: &str,
        qtype: u16,
    ) -> io::Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        let now = i64::try_from(now).map_err(io::Error::other)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?;
        let expires_at: Option<i64> = connection
            .query_row(
                "SELECT expires_at FROM rdrc_cache
                 WHERE cache_id = ?1 AND transport = ?2
                   AND qname = ?3 AND qtype = ?4",
                params![self.cache_id, transport, qname, qtype],
                |row| row.get(0),
            )
            .optional()
            .map_err(io::Error::other)?;
        if expires_at.is_some_and(|expires_at| expires_at <= now) {
            connection
                .execute(
                    "DELETE FROM rdrc_cache
                     WHERE cache_id = ?1 AND transport = ?2
                       AND qname = ?3 AND qtype = ?4",
                    params![self.cache_id, transport, qname, qtype],
                )
                .map_err(io::Error::other)?;
            return Ok(false);
        }
        Ok(expires_at.is_some())
    }

    pub fn save_rdrc(
        &self,
        transport: &str,
        qname: &str,
        qtype: u16,
        timeout: Duration,
    ) -> io::Result<()> {
        let expires_at = SystemTime::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("RDRC expiry overflow"))?
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        let expires_at = i64::try_from(expires_at).map_err(io::Error::other)?;
        self.connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .execute(
                "INSERT INTO rdrc_cache
                    (cache_id, transport, qname, qtype, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (cache_id, transport, qname, qtype)
                 DO UPDATE SET expires_at = excluded.expires_at",
                params![self.cache_id, transport, qname, qtype, expires_at],
            )
            .map_err(io::Error::other)?;
        Ok(())
    }

    fn load_runtime_state(
        &self,
        kind: &str,
        name: &str,
    ) -> io::Result<Option<String>> {
        self.connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .query_row(
                "SELECT value FROM runtime_state
                 WHERE cache_id = ?1 AND kind = ?2 AND name = ?3",
                params![self.cache_id, kind, name],
                |row| row.get(0),
            )
            .optional()
            .map_err(io::Error::other)
    }

    fn save_runtime_state(
        &self,
        kind: &str,
        name: &str,
        value: &str,
    ) -> io::Result<()> {
        self.connection
            .lock()
            .map_err(|_| io::Error::other("persistent cache mutex poisoned"))?
            .execute(
                "INSERT INTO runtime_state (cache_id, kind, name, value)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (cache_id, kind, name)
                 DO UPDATE SET value = excluded.value",
                params![self.cache_id, kind, name, value],
            )
            .map_err(io::Error::other)?;
        Ok(())
    }
}

fn parse_optional<T>(value: Option<String>) -> io::Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value
        .map(|value| value.parse().map_err(io::Error::other))
        .transpose()
}

fn display_optional<T: std::fmt::Display>(value: Option<T>) -> Option<String> {
    value.map(|value| value.to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        time::{Duration, SystemTime},
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };

    use super::{
        PersistentDnsCache, PersistentFakeIpMetadata, PersistentRuleSetEntry,
    };

    #[test]
    fn round_trips_wire_message_and_partitions_cache_ids() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let first = PersistentDnsCache::open(&path, "one").unwrap();
        let second = PersistentDnsCache::open(&path, "two").unwrap();
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("example.com.").unwrap();
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let expiry = SystemTime::now() + Duration::from_secs(60);
        first
            .save("udp", "example.com.", 1, None, None, &message, expiry)
            .unwrap();
        let loaded = first
            .load("udp", "example.com.", 1, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.message, message);
        assert!(loaded.expires_at <= expiry);
        assert!(
            second
                .load("udp", "example.com.", 1, None, None)
                .unwrap()
                .is_none()
        );
        first.clear().unwrap();
        assert!(
            first
                .load("udp", "example.com.", 1, None, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fakeip_rows_are_bidirectional_and_replace_collisions() {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            PersistentDnsCache::open(directory.path().join("cache.db"), "one")
                .unwrap();
        let first = "198.18.0.2".parse::<IpAddr>().unwrap();
        let second = "198.18.0.3".parse::<IpAddr>().unwrap();
        cache.save_fakeip(first, "example.com").unwrap();
        assert_eq!(
            cache.load_fakeip_by_address(first).unwrap().as_deref(),
            Some("example.com")
        );
        assert_eq!(
            cache.load_fakeip_by_domain("example.com", false).unwrap(),
            Some(first)
        );

        cache.save_fakeip(second, "example.com").unwrap();
        assert_eq!(cache.load_fakeip_by_address(first).unwrap(), None);
        cache.save_fakeip(second, "other.test").unwrap();
        assert_eq!(
            cache.load_fakeip_by_domain("example.com", false).unwrap(),
            None
        );
        assert_eq!(
            cache.load_fakeip_by_address(second).unwrap().as_deref(),
            Some("other.test")
        );
    }

    #[test]
    fn fakeip_metadata_round_trips_and_clear_is_namespaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let first = PersistentDnsCache::open(&path, "one").unwrap();
        let second = PersistentDnsCache::open(&path, "two").unwrap();
        let metadata = PersistentFakeIpMetadata {
            inet4_range: Some("198.18.0.0/15".parse().unwrap()),
            inet6_range: Some("fc00::/18".parse().unwrap()),
            current4: Some("198.18.0.7".parse().unwrap()),
            current6: Some("fc00::9".parse().unwrap()),
        };
        first.save_fakeip_metadata(&metadata).unwrap();
        first
            .save_fakeip("198.18.0.7".parse().unwrap(), "example.com")
            .unwrap();
        second
            .save_fakeip("198.18.0.8".parse().unwrap(), "example.org")
            .unwrap();
        assert_eq!(first.load_fakeip_metadata().unwrap(), Some(metadata));
        first.clear_fakeip().unwrap();
        assert_eq!(first.load_fakeip_metadata().unwrap(), None);
        assert_eq!(
            second.load_fakeip_by_domain("example.org", false).unwrap(),
            Some("198.18.0.8".parse().unwrap())
        );
    }

    #[test]
    fn runtime_selection_and_mode_are_namespaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let first = PersistentDnsCache::open(&path, "one").unwrap();
        let second = PersistentDnsCache::open(&path, "two").unwrap();
        first.save_selected("proxy", "direct").unwrap();
        first.save_mode("global").unwrap();
        first.save_group_expand("proxy", true).unwrap();
        second.save_selected("proxy", "block").unwrap();
        assert_eq!(
            first.load_selected("proxy").unwrap().as_deref(),
            Some("direct")
        );
        assert_eq!(
            second.load_selected("proxy").unwrap().as_deref(),
            Some("block")
        );
        assert_eq!(first.load_mode().unwrap().as_deref(), Some("global"));
        assert_eq!(second.load_mode().unwrap(), None);
        assert_eq!(first.load_group_expand("proxy").unwrap(), Some(true));
        assert_eq!(second.load_group_expand("proxy").unwrap(), None);
        first.save_group_expand("proxy", false).unwrap();
        assert_eq!(first.load_group_expand("proxy").unwrap(), Some(false));
    }

    #[test]
    fn rule_set_entries_round_trip_and_are_namespaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let first = PersistentDnsCache::open(&path, "one").unwrap();
        let second = PersistentDnsCache::open(&path, "two").unwrap();
        let entry = PersistentRuleSetEntry {
            content: b"rule-set".to_vec(),
            last_updated: SystemTime::UNIX_EPOCH + Duration::from_secs(123),
            etag: "v1".into(),
            url_hash: vec![1, 2, 3],
        };
        first.save_rule_set("remote", &entry).unwrap();
        assert_eq!(first.load_rule_set("remote").unwrap(), Some(entry));
        assert_eq!(second.load_rule_set("remote").unwrap(), None);
    }

    #[test]
    fn rdrc_entries_expire_and_are_namespaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let first = PersistentDnsCache::open(&path, "one").unwrap();
        let second = PersistentDnsCache::open(&path, "two").unwrap();
        first
            .save_rdrc("remote", "example.com.", 1, Duration::from_secs(60))
            .unwrap();
        assert!(first.load_rdrc("remote", "example.com.", 1).unwrap());
        assert!(!second.load_rdrc("remote", "example.com.", 1).unwrap());
        first
            .save_rdrc("remote", "expired.test.", 28, Duration::ZERO)
            .unwrap();
        assert!(!first.load_rdrc("remote", "expired.test.", 28).unwrap());
    }
}
