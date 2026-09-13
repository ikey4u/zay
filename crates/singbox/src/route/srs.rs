//! Reader for sing-box's binary SRS rule-set format.

use std::{
    collections::HashSet,
    io::{BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use ipnet::IpNet;
use serde_json::{Map, Value};

use crate::option::DnsQueryType;

const MAGIC: &[u8; 3] = b"SRS";
const VERSION_CURRENT: u8 = 5;
const MAX_COLLECTION_LENGTH: u64 = 16 * 1024 * 1024;
const MAX_LOGICAL_DEPTH: usize = 100;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xff;

#[cfg(test)]
fn read(content: &[u8]) -> Result<Vec<Value>, String> {
    read_with_version(content).map(|(_, rules)| rules)
}

pub(super) fn read_with_version(
    content: &[u8],
) -> Result<(u8, Vec<Value>), String> {
    let (version, rules) = read_runtime_with_version(content)?;
    let rules = rules
        .into_iter()
        .map(RuntimeRule::recover)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((version, rules))
}

pub(super) fn read_runtime(content: &[u8]) -> Result<Vec<RuntimeRule>, String> {
    read_runtime_with_version(content).map(|(_, rules)| rules)
}

fn read_runtime_with_version(
    content: &[u8],
) -> Result<(u8, Vec<RuntimeRule>), String> {
    let mut outer = content;
    let mut magic = [0_u8; 3];
    outer
        .read_exact(&mut magic)
        .map_err(|error| error.to_string())?;
    if &magic != MAGIC {
        return Err("invalid sing-box rule-set file".into());
    }
    let version = read_u8(&mut outer)?;
    if version > VERSION_CURRENT {
        return Err(format!("unsupported version: {version}"));
    }
    let decoder = ZlibDecoder::new(outer);
    let mut reader = BufReader::new(decoder);
    let count = read_length(&mut reader)?;
    let mut rules = Vec::with_capacity(count);
    for index in 0..count {
        rules.push(
            read_runtime_rule(&mut reader, 0)
                .map_err(|error| format!("read rule[{index}]: {error}"))?,
        );
    }
    Ok((version, rules))
}

pub(super) enum RuntimeRule {
    Default(Box<RuntimeDefaultRule>),
    Logical {
        mode: RuntimeLogicalMode,
        rules: Vec<RuntimeRule>,
        invert: bool,
    },
}

pub(super) struct RuntimeDefaultRule {
    pub(super) value: Value,
    pub(super) domain: Option<SuccinctSet>,
    pub(super) adguard: Option<SuccinctSet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeLogicalMode {
    And,
    Or,
}

impl RuntimeRule {
    fn recover(self) -> Result<Value, String> {
        match self {
            Self::Default(rule) => {
                let RuntimeDefaultRule {
                    mut value,
                    domain,
                    adguard,
                } = *rule;
                let object = value
                    .as_object_mut()
                    .expect("runtime default rule is an object");
                if let Some(domain) = domain {
                    let (domains, suffixes) =
                        dump_domain_matcher(domain.keys()?)?;
                    insert_array(object, "domain", domains);
                    insert_array(object, "domain_suffix", suffixes);
                }
                if let Some(adguard) = adguard {
                    insert_array(
                        object,
                        "adguard_domain",
                        dump_adguard_matcher(adguard.keys()?)?,
                    );
                }
                Ok(value)
            }
            Self::Logical {
                mode,
                rules,
                invert,
            } => {
                let rules = rules
                    .into_iter()
                    .map(Self::recover)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut object = Map::new();
                object.insert("type".into(), Value::String("logical".into()));
                object.insert(
                    "mode".into(),
                    Value::String(
                        match mode {
                            RuntimeLogicalMode::And => "and",
                            RuntimeLogicalMode::Or => "or",
                        }
                        .into(),
                    ),
                );
                object.insert("rules".into(), Value::Array(rules));
                if invert {
                    object.insert("invert".into(), Value::Bool(true));
                }
                Ok(Value::Object(object))
            }
        }
    }
}

pub(super) fn write(rules: &[Value], version: u8) -> Result<Vec<u8>, String> {
    if !(1..=VERSION_CURRENT).contains(&version) {
        return Err(format!("unknown rule-set version: {version}"));
    }
    let mut payload = Vec::new();
    write_uvarint(&mut payload, rules.len() as u64)?;
    for rule in rules {
        write_rule(&mut payload, rule, version, 0)?;
    }
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.push(version);
    let mut compressor = ZlibEncoder::new(output, Compression::best());
    compressor
        .write_all(&payload)
        .map_err(|error| error.to_string())?;
    compressor.finish().map_err(|error| error.to_string())
}

pub(super) fn downgrade_version(rules: &[Value], mut version: u8) -> u8 {
    if version == 5 && !has_field_recursive(rules, "package_name_regex") {
        version = 4;
    }
    if version == 4
        && !has_field_recursive(rules, "network_interface_address")
        && !has_field_recursive(rules, "default_interface_address")
    {
        version = 3;
    }
    if version == 3
        && !has_field_recursive(rules, "network_type")
        && !has_truthy_recursive(rules, "network_is_expensive")
        && !has_truthy_recursive(rules, "network_is_constrained")
    {
        version = 2;
    }
    version
}

fn has_field_recursive(rules: &[Value], field: &str) -> bool {
    rules.iter().any(|rule| {
        rule.get(field).is_some_and(|value| match value {
            Value::Array(values) => !values.is_empty(),
            Value::Object(values) => !values.is_empty(),
            Value::Null => false,
            _ => true,
        }) || rule
            .get("rules")
            .and_then(Value::as_array)
            .is_some_and(|rules| has_field_recursive(rules, field))
    })
}

fn has_truthy_recursive(rules: &[Value], field: &str) -> bool {
    rules.iter().any(|rule| {
        rule.get(field).and_then(Value::as_bool).unwrap_or(false)
            || rule
                .get("rules")
                .and_then(Value::as_array)
                .is_some_and(|rules| has_truthy_recursive(rules, field))
    })
}

fn write_rule(
    writer: &mut impl Write,
    rule: &Value,
    version: u8,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err("logical rule nested too deep".into());
    }
    let object = rule
        .as_object()
        .ok_or_else(|| "headless rule is not an object".to_owned())?;
    match object.get("type").and_then(Value::as_str).unwrap_or("") {
        "" | "default" => write_default_rule(writer, object, version),
        "logical" => write_logical_rule(writer, object, version, depth),
        kind => Err(format!("unknown headless rule type: {kind}")),
    }
}

fn write_default_rule(
    writer: &mut impl Write,
    object: &Map<String, Value>,
    version: u8,
) -> Result<(), String> {
    writer.write_all(&[0]).map_err(|error| error.to_string())?;
    let query_types = dns_query_type_values(object)?;
    if !query_types.is_empty() {
        write_u16_item(writer, ITEM_QUERY_TYPE, &query_types)?;
    }
    write_optional_string_item(writer, object, "network", ITEM_NETWORK)?;
    let domains = string_values(object, "domain")?;
    let suffixes = string_values(object, "domain_suffix")?;
    if !domains.is_empty() || !suffixes.is_empty() {
        writer
            .write_all(&[ITEM_DOMAIN])
            .map_err(|error| error.to_string())?;
        let keys = build_domain_keys(&domains, &suffixes, version == 1)?;
        write_succinct_set(writer, &keys)?;
    }
    write_optional_string_item(
        writer,
        object,
        "domain_keyword",
        ITEM_DOMAIN_KEYWORD,
    )?;
    write_optional_string_item(
        writer,
        object,
        "domain_regex",
        ITEM_DOMAIN_REGEX,
    )?;
    write_optional_ip_set(
        writer,
        object,
        "source_ip_cidr",
        ITEM_SOURCE_IP_CIDR,
    )?;
    write_optional_ip_set(writer, object, "ip_cidr", ITEM_IP_CIDR)?;
    write_optional_u16_item(writer, object, "source_port", ITEM_SOURCE_PORT)?;
    write_optional_string_item(
        writer,
        object,
        "source_port_range",
        ITEM_SOURCE_PORT_RANGE,
    )?;
    write_optional_u16_item(writer, object, "port", ITEM_PORT)?;
    write_optional_string_item(writer, object, "port_range", ITEM_PORT_RANGE)?;
    write_optional_string_item(
        writer,
        object,
        "process_name",
        ITEM_PROCESS_NAME,
    )?;
    write_optional_string_item(
        writer,
        object,
        "process_path",
        ITEM_PROCESS_PATH,
    )?;
    write_optional_string_item(
        writer,
        object,
        "process_path_regex",
        ITEM_PROCESS_PATH_REGEX,
    )?;
    write_optional_string_item(
        writer,
        object,
        "package_name",
        ITEM_PACKAGE_NAME,
    )?;
    let package_regex = string_values(object, "package_name_regex")?;
    if !package_regex.is_empty() {
        if version < 5 {
            return Err(
                "`package_name_regex` rule item is only supported in version 5 or later"
                    .into(),
            );
        }
        write_string_item(writer, ITEM_PACKAGE_NAME_REGEX, &package_regex)?;
    }
    let network_types = string_values(object, "network_type")?;
    if !network_types.is_empty() {
        if version < 3 {
            return Err(
                "`network_type` rule item is only supported in version 3 or later"
                    .into(),
            );
        }
        let values = network_types
            .iter()
            .map(|value| interface_type_id(value))
            .collect::<Result<Vec<_>, _>>()?;
        write_u8_item(writer, ITEM_NETWORK_TYPE, &values)?;
    }
    if bool_value(object, "network_is_expensive")? {
        if version < 3 {
            return Err("`network_is_expensive` rule item is only supported in version 3 or later".into());
        }
        writer
            .write_all(&[ITEM_NETWORK_IS_EXPENSIVE])
            .map_err(|error| error.to_string())?;
    }
    if bool_value(object, "network_is_constrained")? {
        if version < 3 {
            return Err("`network_is_constrained` rule item is only supported in version 3 or later".into());
        }
        writer
            .write_all(&[ITEM_NETWORK_IS_CONSTRAINED])
            .map_err(|error| error.to_string())?;
    }
    if let Some(addresses) = object.get("network_interface_address") {
        let addresses = addresses.as_object().ok_or_else(|| {
            "network_interface_address is not an object".to_owned()
        })?;
        if !addresses.is_empty() {
            if version < 4 {
                return Err("`network_interface_address` rule item is only supported in version 4 or later".into());
            }
            writer
                .write_all(&[ITEM_NETWORK_INTERFACE_ADDRESS])
                .map_err(|error| error.to_string())?;
            write_uvarint(writer, addresses.len() as u64)?;
            for (kind, prefixes) in addresses {
                writer
                    .write_all(&[interface_type_id(kind)?])
                    .map_err(|error| error.to_string())?;
                let prefixes = value_strings(prefixes)?;
                write_uvarint(writer, prefixes.len() as u64)?;
                for prefix in prefixes {
                    write_prefix(writer, &prefix)?;
                }
            }
        }
    }
    let default_addresses = string_values(object, "default_interface_address")?;
    if !default_addresses.is_empty() {
        if version < 4 {
            return Err("`default_interface_address` rule item is only supported in version 4 or later".into());
        }
        writer
            .write_all(&[ITEM_DEFAULT_INTERFACE_ADDRESS])
            .map_err(|error| error.to_string())?;
        write_uvarint(writer, default_addresses.len() as u64)?;
        for prefix in default_addresses {
            write_prefix(writer, &prefix)?;
        }
    }
    write_optional_string_item(writer, object, "wifi_ssid", ITEM_WIFI_SSID)?;
    write_optional_string_item(writer, object, "wifi_bssid", ITEM_WIFI_BSSID)?;
    let adguard = string_values(object, "adguard_domain")?;
    if !adguard.is_empty() {
        if version < 2 {
            return Err(
                "AdGuard rule items are only supported in version 2 or later"
                    .into(),
            );
        }
        writer
            .write_all(&[ITEM_ADGUARD_DOMAIN])
            .map_err(|error| error.to_string())?;
        let keys = build_adguard_keys(&adguard)?;
        write_succinct_set(writer, &keys)?;
    }
    writer
        .write_all(&[ITEM_FINAL, u8::from(bool_value(object, "invert")?)])
        .map_err(|error| error.to_string())
}

fn write_logical_rule(
    writer: &mut impl Write,
    object: &Map<String, Value>,
    version: u8,
    depth: usize,
) -> Result<(), String> {
    let mode = match object.get("mode").and_then(Value::as_str) {
        Some("and") => 0,
        Some("or") => 1,
        Some(mode) => return Err(format!("unknown logical mode: {mode}")),
        None => return Err("logical rule missing mode".into()),
    };
    let rules = object
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| "logical rule missing rules".to_owned())?;
    writer
        .write_all(&[1, mode])
        .map_err(|error| error.to_string())?;
    write_uvarint(writer, rules.len() as u64)?;
    for rule in rules {
        write_rule(writer, rule, version, depth + 1)?;
    }
    writer
        .write_all(&[u8::from(bool_value(object, "invert")?)])
        .map_err(|error| error.to_string())
}

fn string_values(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, String> {
    object
        .get(key)
        .map(value_strings)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn value_strings(value: &Value) -> Result<Vec<String>, String> {
    let values = match value {
        Value::Null => return Ok(Vec::new()),
        Value::Array(values) => values.as_slice(),
        value => std::slice::from_ref(value),
    };
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "rule item is not a string".to_owned())
        })
        .collect()
}

fn u16_values(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Vec<u16>, String> {
    let Some(value) = object.get(key) else {
        return Ok(Vec::new());
    };
    let values = match value {
        Value::Null => return Ok(Vec::new()),
        Value::Array(values) => values.as_slice(),
        value => std::slice::from_ref(value),
    };
    values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| "rule item is not a uint16".to_owned())
        })
        .collect()
}

fn dns_query_type_values(
    object: &Map<String, Value>,
) -> Result<Vec<u16>, String> {
    let Some(value) = object.get("query_type") else {
        return Ok(Vec::new());
    };
    let values = match value {
        Value::Null => return Ok(Vec::new()),
        Value::Array(values) => values.as_slice(),
        value => std::slice::from_ref(value),
    };
    values
        .iter()
        .map(|value| {
            serde_json::from_value::<DnsQueryType>(value.clone())
                .map(|query_type| query_type.0)
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn bool_value(object: &Map<String, Value>, key: &str) -> Result<bool, String> {
    object
        .get(key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("{key} is not a boolean"))
        })
        .transpose()
        .map(|value| value.unwrap_or(false))
}

fn write_optional_string_item(
    writer: &mut impl Write,
    object: &Map<String, Value>,
    key: &str,
    item: u8,
) -> Result<(), String> {
    let values = string_values(object, key)?;
    if !values.is_empty() {
        write_string_item(writer, item, &values)?;
    }
    Ok(())
}

fn write_string_item(
    writer: &mut impl Write,
    item: u8,
    values: &[String],
) -> Result<(), String> {
    writer
        .write_all(&[item])
        .map_err(|error| error.to_string())?;
    write_uvarint(writer, values.len() as u64)?;
    for value in values {
        write_uvarint(writer, value.len() as u64)?;
        writer
            .write_all(value.as_bytes())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_optional_u16_item(
    writer: &mut impl Write,
    object: &Map<String, Value>,
    key: &str,
    item: u8,
) -> Result<(), String> {
    let values = u16_values(object, key)?;
    if values.is_empty() {
        return Ok(());
    }
    write_u16_item(writer, item, &values)
}

fn write_u16_item(
    writer: &mut impl Write,
    item: u8,
    values: &[u16],
) -> Result<(), String> {
    writer
        .write_all(&[item])
        .map_err(|error| error.to_string())?;
    write_uvarint(writer, values.len() as u64)?;
    for value in values {
        writer
            .write_all(&value.to_be_bytes())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_u8_item(
    writer: &mut impl Write,
    item: u8,
    values: &[u8],
) -> Result<(), String> {
    writer
        .write_all(&[item])
        .map_err(|error| error.to_string())?;
    write_uvarint(writer, values.len() as u64)?;
    writer.write_all(values).map_err(|error| error.to_string())
}

fn build_domain_keys(
    domains: &[String],
    suffixes: &[String],
    legacy: bool,
) -> Result<Vec<Vec<u8>>, String> {
    let mut keys = Vec::new();
    let mut seen = HashSet::new();
    for domain in suffixes {
        if domain.is_empty() {
            return Err("empty domain suffix".into());
        }
        if !seen.insert(domain.clone()) {
            continue;
        }
        if domain.starts_with('.') {
            keys.push(reverse_domain(&format!("\r{domain}")));
        } else if legacy {
            keys.push(reverse_domain(domain));
            let dotted = format!(".{domain}");
            if seen.insert(dotted.clone()) {
                keys.push(reverse_domain(&format!("\r{dotted}")));
            }
        } else {
            keys.push(reverse_domain(&format!("\n{domain}")));
        }
    }
    for domain in domains {
        if domain.is_empty() {
            return Err("empty domain".into());
        }
        if seen.insert(domain.clone()) {
            keys.push(reverse_domain(domain));
        }
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn build_adguard_keys(rules: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut keys = Vec::with_capacity(rules.len());
    for original in rules {
        let mut rule = original.as_str();
        let mut suffix = false;
        let mut start = false;
        if let Some(value) = rule.strip_prefix("||") {
            rule = value;
            suffix = true;
        } else if let Some(value) = rule.strip_prefix('|') {
            rule = value;
            start = true;
        }
        let end = rule.ends_with('^');
        if end {
            rule = &rule[..rule.len() - 1];
        }
        let mut encoded = if suffix {
            format!("\n{rule}")
        } else if start {
            rule.to_owned()
        } else {
            format!("\r{rule}")
        };
        if !end {
            encoded = encoded.trim_end_matches('.').to_owned();
            encoded.push('\u{8}');
        }
        if encoded.is_empty() {
            return Err("empty AdGuard domain rule".into());
        }
        keys.push(reverse_domain(&encoded));
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

fn reverse_domain(value: &str) -> Vec<u8> {
    value.chars().rev().collect::<String>().into_bytes()
}

fn write_succinct_set(
    writer: &mut impl Write,
    keys: &[Vec<u8>],
) -> Result<(), String> {
    if keys.is_empty() {
        return Err("cannot encode empty succinct set".into());
    }
    let mut leaves = Vec::new();
    let mut bitmap = Vec::new();
    let mut labels = Vec::new();
    let mut bitmap_index = 0;
    let mut queue = vec![(0_usize, keys.len(), 0_usize)];
    let mut index = 0;
    while index < queue.len() {
        let (mut start, end, column) = queue[index];
        if keys.get(start).is_some_and(|key| column == key.len()) {
            start += 1;
            set_bit(&mut leaves, index);
        }
        let mut cursor = start;
        while cursor < end {
            let first = cursor;
            let label = *keys[cursor]
                .get(column)
                .ok_or_else(|| "malformed domain key".to_owned())?;
            cursor += 1;
            while cursor < end && keys[cursor][column] == label {
                cursor += 1;
            }
            queue.push((first, cursor, column + 1));
            labels.push(label);
            bitmap_index += 1;
        }
        set_bit(&mut bitmap, bitmap_index);
        bitmap_index += 1;
        index += 1;
    }
    writer.write_all(&[0]).map_err(|error| error.to_string())?;
    write_u64_slice(writer, &leaves)?;
    write_u64_slice(writer, &bitmap)?;
    write_uvarint(writer, labels.len() as u64)?;
    writer.write_all(&labels).map_err(|error| error.to_string())
}

fn set_bit(words: &mut Vec<u64>, index: usize) {
    words.resize(words.len().max(index / 64 + 1), 0);
    words[index / 64] |= 1_u64 << (index % 64);
}

fn write_u64_slice(
    writer: &mut impl Write,
    values: &[u64],
) -> Result<(), String> {
    write_uvarint(writer, values.len() as u64)?;
    for value in values {
        writer
            .write_all(&value.to_be_bytes())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct IpRange {
    family: u8,
    from: u128,
    to: u128,
}

fn write_optional_ip_set(
    writer: &mut impl Write,
    object: &Map<String, Value>,
    key: &str,
    item: u8,
) -> Result<(), String> {
    let prefixes = string_values(object, key)?;
    if prefixes.is_empty() {
        return Ok(());
    }
    let mut ranges = prefixes
        .iter()
        .map(|value| parse_ip_range(value))
        .collect::<Result<Vec<_>, _>>()?;
    ranges.sort_by_key(|range| (range.family, range.from, range.to));
    let mut merged: Vec<IpRange> = Vec::new();
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && previous.family == range.family
            && range.from <= previous.to.saturating_add(1)
        {
            previous.to = previous.to.max(range.to);
        } else {
            merged.push(range);
        }
    }
    writer
        .write_all(&[item, 1])
        .map_err(|error| error.to_string())?;
    writer
        .write_all(&(merged.len() as u64).to_be_bytes())
        .map_err(|error| error.to_string())?;
    for range in merged {
        write_ip_addr(writer, range.family, range.from)?;
        write_ip_addr(writer, range.family, range.to)?;
    }
    Ok(())
}

fn parse_ip_range(value: &str) -> Result<IpRange, String> {
    let prefix = parse_prefix(value)?;
    match prefix {
        IpNet::V4(prefix) => Ok(IpRange {
            family: 4,
            from: u32::from(prefix.network()) as u128,
            to: u32::from(prefix.broadcast()) as u128,
        }),
        IpNet::V6(prefix) => {
            let from = u128::from(prefix.network());
            let host_bits = 128 - prefix.prefix_len();
            let to = if host_bits == 128 {
                u128::MAX
            } else {
                from | ((1_u128 << host_bits) - 1)
            };
            Ok(IpRange {
                family: 6,
                from,
                to,
            })
        }
    }
}

fn parse_prefix(value: &str) -> Result<IpNet, String> {
    if let Ok(prefix) = value.parse::<IpNet>() {
        return Ok(prefix);
    }
    let address = value.parse::<IpAddr>().map_err(|error| error.to_string())?;
    IpNet::new(address, if address.is_ipv4() { 32 } else { 128 })
        .map_err(|error| error.to_string())
}

fn write_prefix(writer: &mut impl Write, value: &str) -> Result<(), String> {
    let prefix = parse_prefix(value)?;
    write_ip_address(writer, prefix.addr())?;
    writer
        .write_all(&[prefix.prefix_len()])
        .map_err(|error| error.to_string())
}

fn write_ip_address(
    writer: &mut impl Write,
    address: IpAddr,
) -> Result<(), String> {
    match address {
        IpAddr::V4(address) => {
            write_uvarint(writer, 4)?;
            writer
                .write_all(&address.octets())
                .map_err(|error| error.to_string())
        }
        IpAddr::V6(address) => {
            write_uvarint(writer, 16)?;
            writer
                .write_all(&address.octets())
                .map_err(|error| error.to_string())
        }
    }
}

fn write_ip_addr(
    writer: &mut impl Write,
    family: u8,
    address: u128,
) -> Result<(), String> {
    match family {
        4 => {
            write_ip_address(writer, IpAddr::V4(Ipv4Addr::from(address as u32)))
        }
        6 => write_ip_address(writer, IpAddr::V6(Ipv6Addr::from(address))),
        _ => Err(format!("unknown IP family: {family}")),
    }
}

fn interface_type_id(value: &str) -> Result<u8, String> {
    match value {
        "wifi" => Ok(0),
        "cellular" => Ok(1),
        "ethernet" => Ok(2),
        "other" => Ok(3),
        _ => Err(format!("unknown interface type: {value}")),
    }
}

fn write_uvarint(
    writer: &mut impl Write,
    mut value: u64,
) -> Result<(), String> {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer
            .write_all(&[byte])
            .map_err(|error| error.to_string())?;
        if value == 0 {
            return Ok(());
        }
    }
}

fn read_runtime_rule(
    reader: &mut impl Read,
    depth: usize,
) -> Result<RuntimeRule, String> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err("logical rule nested too deep".into());
    }
    match read_u8(reader)? {
        0 => read_runtime_default_rule(reader),
        1 => read_runtime_logical_rule(reader, depth),
        kind => Err(format!("unknown rule type: {kind}")),
    }
}

fn read_runtime_default_rule(
    reader: &mut impl Read,
) -> Result<RuntimeRule, String> {
    let mut object = Map::new();
    let mut domain = None;
    let mut adguard = None;
    let mut last_item: Option<u8> = None;
    loop {
        let item = read_u8(reader)?;
        match item {
            ITEM_QUERY_TYPE => {
                let values = read_u16_slice(reader)?
                    .into_iter()
                    .map(|value| {
                        serde_json::to_value(DnsQueryType(value))
                            .map_err(|error| error.to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                object.insert("query_type".into(), Value::Array(values));
            }
            ITEM_NETWORK => {
                insert_array(
                    &mut object,
                    "network",
                    read_string_slice(reader)?,
                );
            }
            ITEM_DOMAIN => {
                domain = Some(SuccinctSet::read(reader)?);
            }
            ITEM_DOMAIN_KEYWORD => insert_array(
                &mut object,
                "domain_keyword",
                read_string_slice(reader)?,
            ),
            ITEM_DOMAIN_REGEX => insert_array(
                &mut object,
                "domain_regex",
                read_string_slice(reader)?,
            ),
            ITEM_SOURCE_IP_CIDR => insert_array(
                &mut object,
                "source_ip_cidr",
                read_ip_set(reader)?,
            ),
            ITEM_IP_CIDR => {
                insert_array(&mut object, "ip_cidr", read_ip_set(reader)?);
            }
            ITEM_SOURCE_PORT => insert_array(
                &mut object,
                "source_port",
                read_u16_slice(reader)?,
            ),
            ITEM_SOURCE_PORT_RANGE => insert_array(
                &mut object,
                "source_port_range",
                read_string_slice(reader)?,
            ),
            ITEM_PORT => {
                insert_array(&mut object, "port", read_u16_slice(reader)?);
            }
            ITEM_PORT_RANGE => insert_array(
                &mut object,
                "port_range",
                read_string_slice(reader)?,
            ),
            ITEM_PROCESS_NAME => insert_array(
                &mut object,
                "process_name",
                read_string_slice(reader)?,
            ),
            ITEM_PROCESS_PATH => insert_array(
                &mut object,
                "process_path",
                read_string_slice(reader)?,
            ),
            ITEM_PROCESS_PATH_REGEX => insert_array(
                &mut object,
                "process_path_regex",
                read_string_slice(reader)?,
            ),
            ITEM_PACKAGE_NAME => insert_array(
                &mut object,
                "package_name",
                read_string_slice(reader)?,
            ),
            ITEM_PACKAGE_NAME_REGEX => insert_array(
                &mut object,
                "package_name_regex",
                read_string_slice(reader)?,
            ),
            ITEM_WIFI_SSID => insert_array(
                &mut object,
                "wifi_ssid",
                read_string_slice(reader)?,
            ),
            ITEM_WIFI_BSSID => insert_array(
                &mut object,
                "wifi_bssid",
                read_string_slice(reader)?,
            ),
            ITEM_ADGUARD_DOMAIN => {
                adguard = Some(SuccinctSet::read(reader)?);
            }
            ITEM_NETWORK_TYPE => {
                let values = read_u8_slice(reader)?
                    .into_iter()
                    .map(interface_type_name)
                    .collect::<Result<Vec<_>, _>>()?;
                insert_array(&mut object, "network_type", values);
            }
            ITEM_NETWORK_IS_EXPENSIVE => {
                object.insert("network_is_expensive".into(), Value::Bool(true));
            }
            ITEM_NETWORK_IS_CONSTRAINED => {
                object
                    .insert("network_is_constrained".into(), Value::Bool(true));
            }
            ITEM_NETWORK_INTERFACE_ADDRESS => {
                let count = read_length(reader)?;
                let mut addresses = Map::new();
                for _ in 0..count {
                    let kind = interface_type_name(read_u8(reader)?)?;
                    let prefix_count = read_length(reader)?;
                    let mut prefixes = Vec::with_capacity(prefix_count);
                    for _ in 0..prefix_count {
                        prefixes.push(Value::String(read_prefix(reader)?));
                    }
                    addresses.insert(kind, Value::Array(prefixes));
                }
                object.insert(
                    "network_interface_address".into(),
                    Value::Object(addresses),
                );
            }
            ITEM_DEFAULT_INTERFACE_ADDRESS => {
                let count = read_length(reader)?;
                let mut prefixes = Vec::with_capacity(count);
                for _ in 0..count {
                    prefixes.push(read_prefix(reader)?);
                }
                insert_array(
                    &mut object,
                    "default_interface_address",
                    prefixes,
                );
            }
            ITEM_FINAL => {
                let invert = read_u8(reader)? != 0;
                if invert {
                    object.insert("invert".into(), Value::Bool(true));
                }
                return Ok(RuntimeRule::Default(Box::new(
                    RuntimeDefaultRule {
                        value: Value::Object(object),
                        domain,
                        adguard,
                    },
                )));
            }
            unknown => {
                return Err(format!(
                    "unknown rule item type: {unknown}, last type: {}",
                    last_item
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".into())
                ));
            }
        }
        last_item = Some(item);
    }
}

fn read_runtime_logical_rule(
    reader: &mut impl Read,
    depth: usize,
) -> Result<RuntimeRule, String> {
    let mode = match read_u8(reader)? {
        0 => RuntimeLogicalMode::And,
        1 => RuntimeLogicalMode::Or,
        mode => return Err(format!("unknown logical mode: {mode}")),
    };
    let count = read_length(reader)?;
    let mut rules = Vec::with_capacity(count);
    for index in 0..count {
        rules.push(read_runtime_rule(reader, depth + 1).map_err(|error| {
            format!("read logical rule [{index}]: {error}")
        })?);
    }
    let invert = read_u8(reader)? != 0;
    Ok(RuntimeRule::Logical {
        mode,
        rules,
        invert,
    })
}

#[derive(Debug)]
pub(super) struct SuccinctSet {
    leaves: Vec<u64>,
    bitmap: Vec<u64>,
    labels: Vec<u8>,
    select_blocks: Vec<u32>,
    node_count: usize,
}

impl SuccinctSet {
    fn read(reader: &mut impl Read) -> Result<Self, String> {
        let _format = read_u8(reader)?;
        let mut leaves = read_u64_slice(reader)?;
        let bitmap = read_u64_slice(reader)?;
        let labels = read_byte_slice(reader)?;
        let mut select_blocks = Vec::new();
        let mut ones = 0_usize;
        let mut last_one = None;
        for (word_index, word) in bitmap.iter().copied().enumerate() {
            if word != 0 {
                last_one = Some(
                    word_index * 64 + (63 - word.leading_zeros() as usize),
                );
            }
            for bit in 0..64 {
                if word & (1_u64 << bit) != 0 {
                    let position = word_index * 64 + bit;
                    if ones.is_multiple_of(32) {
                        select_blocks.push(position as u32);
                    }
                    ones += 1;
                }
            }
        }
        let last_one = last_one
            .ok_or_else(|| "domain: malformed succinct set".to_owned())?;
        let zeros = last_one + 1 - ones;
        if ones != zeros + 1 || labels.len() != zeros {
            return Err("domain: malformed succinct set".into());
        }
        let leaf_words = ones.div_ceil(64);
        leaves.resize(leaves.len().max(leaf_words), 0);

        Ok(Self {
            leaves,
            bitmap,
            labels,
            select_blocks,
            node_count: ones,
        })
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, String> {
        #[derive(Clone, Copy)]
        struct Frame {
            node: usize,
            position: usize,
        }
        let mut keys = Vec::new();
        let mut key = Vec::new();
        if get_bit(&self.leaves, 0)? {
            keys.push(Vec::new());
        }
        let mut stack = vec![Frame {
            node: 0,
            position: 0,
        }];
        while let Some(frame) = stack.last_mut() {
            if get_bit(&self.bitmap, frame.position)? {
                stack.pop();
                if !stack.is_empty() {
                    key.pop();
                    stack.last_mut().expect("parent frame").position += 1;
                }
                continue;
            }
            let label_index = frame
                .position
                .checked_sub(frame.node)
                .ok_or_else(|| "domain: malformed succinct set".to_owned())?;
            let label = *self
                .labels
                .get(label_index)
                .ok_or_else(|| "domain: malformed succinct set".to_owned())?;
            key.push(label);
            let child = label_index + 1;
            if child >= self.node_count {
                return Err("domain: malformed succinct set".into());
            }
            if get_bit(&self.leaves, child)? {
                keys.push(key.clone());
            }
            stack.push(Frame {
                node: child,
                position: self.node_start(child),
            });
        }
        Ok(keys)
    }

    pub(super) fn matches_domain(&self, domain: &str) -> bool {
        let key = domain.chars().rev().collect::<String>();
        self.matches_domain_key(key.as_bytes())
    }

    fn matches_domain_key(&self, key: &[u8]) -> bool {
        let (mut node, mut bitmap_index) = (0_usize, 0_usize);
        for &current in key {
            loop {
                if self.bit(&self.bitmap, bitmap_index) {
                    return false;
                }
                let Some(label) = self.label(node, bitmap_index) else {
                    return false;
                };
                if label == b'\r' {
                    return true;
                }
                let Some(child) = self.child(node, bitmap_index) else {
                    return false;
                };
                if label == b'\n'
                    && current == b'.'
                    && self.bit(&self.leaves, child)
                {
                    return true;
                }
                if label == current {
                    node = child;
                    bitmap_index = self.node_start(node);
                    break;
                }
                bitmap_index += 1;
            }
        }
        if self.bit(&self.leaves, node) {
            return true;
        }
        loop {
            if self.bit(&self.bitmap, bitmap_index) {
                return false;
            }
            let Some(label) = self.label(node, bitmap_index) else {
                return false;
            };
            if matches!(label, b'\r' | b'\n') {
                return true;
            }
            bitmap_index += 1;
        }
    }

    pub(super) fn matches_adguard(&self, domain: &str) -> bool {
        let reversed = domain.chars().rev().collect::<String>();
        let mut key = reversed.as_bytes();
        if self.matches_adguard_key(key, 0, 0, 0) {
            return true;
        }
        loop {
            let mut suffix_key = Vec::with_capacity(key.len() + 1);
            suffix_key.push(b'\x08');
            suffix_key.extend_from_slice(key);
            if self.matches_adguard_key(&suffix_key, 0, 0, 0) {
                return true;
            }
            let Some(dot) = key.iter().position(|byte| *byte == b'.') else {
                return false;
            };
            key = &key[dot + 1..];
        }
    }

    fn matches_adguard_key(
        &self,
        key: &[u8],
        mut node: usize,
        mut bitmap_index: usize,
        depth: usize,
    ) -> bool {
        if depth > 100 {
            return false;
        }
        for (index, &current) in key.iter().enumerate() {
            loop {
                if self.bit(&self.bitmap, bitmap_index) {
                    return false;
                }
                let Some(label) = self.label(node, bitmap_index) else {
                    return false;
                };
                if label == b'\r' {
                    return true;
                }
                let Some(child) = self.child(node, bitmap_index) else {
                    return false;
                };
                if label == b'\n'
                    && current == b'.'
                    && self.bit(&self.leaves, child)
                {
                    return true;
                }
                if label == current {
                    node = child;
                    bitmap_index = self.node_start(node);
                    break;
                }
                if matches!(label, b'*' | b'\x08') {
                    let child_start = self.node_start(child);
                    if self.matches_adguard_key(
                        &key[index..],
                        child,
                        child_start,
                        depth + 1,
                    ) {
                        return true;
                    }
                    for suffix in index + 1..=key.len() {
                        if self.matches_adguard_key(
                            &key[suffix..],
                            child,
                            child_start,
                            depth + 1,
                        ) {
                            return true;
                        }
                    }
                }
                bitmap_index += 1;
            }
        }
        if self.bit(&self.leaves, node) {
            return true;
        }
        loop {
            if self.bit(&self.bitmap, bitmap_index) {
                return false;
            }
            let Some(label) = self.label(node, bitmap_index) else {
                return false;
            };
            if matches!(label, b'\r' | b'\n' | b'\x08') {
                return true;
            }
            if label == b'*' {
                let Some(child) = self.child(node, bitmap_index) else {
                    return false;
                };
                return self.matches_adguard_key(
                    &[],
                    child,
                    self.node_start(child),
                    depth + 1,
                );
            }
            bitmap_index += 1;
        }
    }

    fn bit(&self, words: &[u64], index: usize) -> bool {
        words
            .get(index / 64)
            .is_some_and(|word| word & (1_u64 << (index % 64)) != 0)
    }

    fn label(&self, node: usize, bitmap_index: usize) -> Option<u8> {
        self.labels.get(bitmap_index.checked_sub(node)?).copied()
    }

    fn child(&self, node: usize, bitmap_index: usize) -> Option<usize> {
        let child = bitmap_index.checked_sub(node)?.checked_add(1)?;
        (child < self.node_count).then_some(child)
    }

    fn node_start(&self, node: usize) -> usize {
        if node == 0 {
            0
        } else {
            self.select_one(node - 1).map_or(0, |position| position + 1)
        }
    }

    fn select_one(&self, index: usize) -> Option<usize> {
        if index >= self.node_count {
            return None;
        }
        let mut position = *self.select_blocks.get(index / 32)? as usize;
        let mut remaining = index % 32;
        while remaining != 0 {
            position = position.checked_add(1)?;
            while !self.bit(&self.bitmap, position) {
                position = position.checked_add(1)?;
            }
            remaining -= 1;
        }
        Some(position)
    }
}

fn dump_domain_matcher(
    keys: Vec<Vec<u8>>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut domains = Vec::new();
    let mut suffixes = Vec::new();
    for key in keys {
        let value = reverse_utf8(key)?;
        if let Some(value) = value.strip_prefix('\r') {
            suffixes.push(value.to_owned());
        } else if let Some(value) = value.strip_prefix('\n') {
            suffixes.push(value.to_owned());
        } else {
            domains.push(value);
        }
    }
    domains.sort();
    domains.dedup();
    suffixes.sort();
    suffixes.dedup();
    Ok((domains, suffixes))
}

fn dump_adguard_matcher(keys: Vec<Vec<u8>>) -> Result<Vec<String>, String> {
    let mut rules = Vec::with_capacity(keys.len());
    for key in keys {
        let mut value = reverse_utf8(key)?;
        let mut is_suffix = false;
        let mut has_start = false;
        if let Some(rest) = value.strip_prefix('\r') {
            value = rest.to_owned();
        } else if let Some(rest) = value.strip_prefix('\n') {
            value = rest.to_owned();
            is_suffix = true;
        } else {
            has_start = true;
        }
        let has_end = if value.ends_with('\u{8}') {
            value.pop();
            false
        } else {
            true
        };
        if is_suffix {
            value = format!("||{value}");
        } else if has_start {
            value = format!("|{value}");
        }
        if has_end {
            value.push('^');
        }
        rules.push(value);
    }
    Ok(rules)
}

fn reverse_utf8(value: Vec<u8>) -> Result<String, String> {
    let value = String::from_utf8(value).map_err(|error| error.to_string())?;
    Ok(value.chars().rev().collect())
}

fn read_ip_set(reader: &mut impl Read) -> Result<Vec<String>, String> {
    if read_u8(reader)? != 1 {
        return Err("invalid IP set version".into());
    }
    let count = read_u64_be(reader)?;
    if count > MAX_COLLECTION_LENGTH {
        return Err("IP set is too large".into());
    }
    let mut prefixes = Vec::new();
    for _ in 0..count {
        let from = read_ip_addr(reader)?;
        let to = read_ip_addr(reader)?;
        prefixes.extend(range_to_prefixes(from, to)?);
    }
    Ok(prefixes)
}

fn range_to_prefixes(from: IpAddr, to: IpAddr) -> Result<Vec<String>, String> {
    match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => range_to_prefixes_inner(
            u32::from_be_bytes(from.octets()) as u128,
            u32::from_be_bytes(to.octets()) as u128,
            32,
            |value, prefix| {
                format!("{}/{}", Ipv4Addr::from(value as u32), prefix)
            },
        ),
        (IpAddr::V6(from), IpAddr::V6(to)) => range_to_prefixes_inner(
            u128::from_be_bytes(from.octets()),
            u128::from_be_bytes(to.octets()),
            128,
            |value, prefix| format!("{}/{}", Ipv6Addr::from(value), prefix),
        ),
        _ => Err("IP set range mixes address families".into()),
    }
}

fn range_to_prefixes_inner(
    mut start: u128,
    end: u128,
    bits: u32,
    render: impl Fn(u128, u32) -> String,
) -> Result<Vec<String>, String> {
    if start > end {
        return Err("invalid descending IP set range".into());
    }
    let maximum = if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << bits) - 1
    };
    if end > maximum {
        return Err("IP set address exceeds its family".into());
    }
    let mut result = Vec::new();
    loop {
        let alignment = if start == 0 {
            bits
        } else {
            start.trailing_zeros().min(bits)
        };
        let capacity = if start == 0 && end == maximum {
            bits
        } else {
            (end - start + 1).ilog2()
        };
        let host_bits = alignment.min(capacity);
        result.push(render(start, bits - host_bits));
        if host_bits == bits {
            break;
        }
        let block = 1_u128 << host_bits;
        if block - 1 == end - start {
            break;
        }
        start += block;
    }
    Ok(result)
}

fn read_prefix(reader: &mut impl Read) -> Result<String, String> {
    let address = read_ip_addr(reader)?;
    let bits = read_u8(reader)?;
    match address {
        IpAddr::V4(address) if bits <= 32 => Ok(format!("{address}/{bits}")),
        IpAddr::V6(address) if bits <= 128 => Ok(format!("{address}/{bits}")),
        _ => Err("invalid IP prefix length".into()),
    }
}

fn read_ip_addr(reader: &mut impl Read) -> Result<IpAddr, String> {
    match read_length(reader)? {
        4 => {
            let mut bytes = [0_u8; 4];
            reader
                .read_exact(&mut bytes)
                .map_err(|error| error.to_string())?;
            Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        16 => {
            let mut bytes = [0_u8; 16];
            reader
                .read_exact(&mut bytes)
                .map_err(|error| error.to_string())?;
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        length => Err(format!("invalid IP address length: {length}")),
    }
}

fn read_string_slice(reader: &mut impl Read) -> Result<Vec<String>, String> {
    let count = read_length(reader)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(
            String::from_utf8(read_byte_slice(reader)?)
                .map_err(|error| error.to_string())?,
        );
    }
    Ok(values)
}

fn read_u8_slice(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let count = read_length(reader)?;
    let mut values = vec![0; count];
    reader
        .read_exact(&mut values)
        .map_err(|error| error.to_string())?;
    Ok(values)
}

fn read_u16_slice(reader: &mut impl Read) -> Result<Vec<u16>, String> {
    let count = read_length(reader)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0_u8; 2];
        reader
            .read_exact(&mut bytes)
            .map_err(|error| error.to_string())?;
        values.push(u16::from_be_bytes(bytes));
    }
    Ok(values)
}

fn read_u64_slice(reader: &mut impl Read) -> Result<Vec<u64>, String> {
    let count = read_length(reader)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_u64_be(reader)?);
    }
    Ok(values)
}

fn read_byte_slice(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let count = read_length(reader)?;
    let mut value = vec![0; count];
    reader
        .read_exact(&mut value)
        .map_err(|error| error.to_string())?;
    Ok(value)
}

fn read_u64_be(reader: &mut impl Read) -> Result<u64, String> {
    let mut bytes = [0_u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_length(reader: &mut impl Read) -> Result<usize, String> {
    let value = read_uvarint(reader)?;
    if value > MAX_COLLECTION_LENGTH {
        return Err(format!("collection is too large: {value}"));
    }
    usize::try_from(value).map_err(|_| "collection length overflow".into())
}

fn read_uvarint(reader: &mut impl Read) -> Result<u64, String> {
    let mut value = 0_u64;
    for index in 0..10 {
        let byte = read_u8(reader)?;
        if index == 9 && byte > 1 {
            return Err("varint overflows a 64-bit integer".into());
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte < 0x80 {
            return Ok(value);
        }
    }
    Err("varint overflows a 64-bit integer".into())
}

fn read_u8(reader: &mut impl Read) -> Result<u8, String> {
    let mut value = [0_u8; 1];
    reader
        .read_exact(&mut value)
        .map_err(|error| error.to_string())?;
    Ok(value[0])
}

fn get_bit(words: &[u64], index: usize) -> Result<bool, String> {
    words
        .get(index / 64)
        .map(|word| word & (1_u64 << (index % 64)) != 0)
        .ok_or_else(|| "domain: malformed succinct set".into())
}

fn interface_type_name(value: u8) -> Result<String, String> {
    match value {
        0 => Ok("wifi".into()),
        1 => Ok("cellular".into()),
        2 => Ok("ethernet".into()),
        3 => Ok("other".into()),
        _ => Err(format!("unknown interface type: {value}")),
    }
}

fn insert_array<T>(object: &mut Map<String, Value>, key: &str, values: Vec<T>)
where
    T: Into<Value>,
{
    if !values.is_empty() {
        object.insert(
            key.into(),
            Value::Array(values.into_iter().map(Into::into).collect()),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use flate2::{Compression, write::ZlibEncoder};

    use super::{
        ITEM_DEFAULT_INTERFACE_ADDRESS, ITEM_DOMAIN, ITEM_DOMAIN_KEYWORD,
        ITEM_IP_CIDR, ITEM_QUERY_TYPE, MAGIC, RuntimeRule, VERSION_CURRENT,
        downgrade_version, range_to_prefixes, read, read_runtime, read_uvarint,
        read_with_version, write,
    };

    const GO_SRS_V5: &str = "U1JTBXjaTJC/buJAEMa/WS9w+PAB97e54gqk68xiQLpzlUdIlQohOfbKcbw2GwOK6fIKeQtk5QEipaHPiyRPsZGxovArZub7FSPNMICB8JuYtQm1tY10HYF7AGBVwx5H0ou/Mt+pUGk3z+QqUG6pc5lJNyg2ZRRKFdhJeSVD17Gok8rd7aqIOA2WhYxluXBlGWRayVGLmnUgftgD/LA3pv3uGLcBcNsYM/hDziNOOApzQodZL9brJ+p6QgjfExPRZTinJ5u6/2rzXwjxmXi4LVSPnPF2XYwvk3xc5yG16jZyyNJp/IvaS53GC/crA/v2/QeB+MMA6P0kHp0B9hfi63US9WkohD+Z+J7nT6f+bObP54aIGJqvAbhrhuuqqvpS6SwopauCMIlXygDtj9ufcYO6GAO8BQAA//9/VWDo";

    fn encode_uvarint(mut value: u64) -> Vec<u8> {
        let mut encoded = Vec::new();
        while value >= 0x80 {
            encoded.push((value as u8) | 0x80);
            value >>= 7;
        }
        encoded.push(value as u8);
        encoded
    }

    fn craft_rule_set(body: &[u8]) -> Vec<u8> {
        let mut content = MAGIC.to_vec();
        content.push(VERSION_CURRENT);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        content.extend(encoder.finish().unwrap());
        content
    }

    fn append(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn reads_go_unsigned_varints() {
        assert_eq!(read_uvarint(&mut &[0xac, 0x02][..]).unwrap(), 300);
        assert!(read_uvarint(&mut &[0xff; 10][..]).is_err());
    }

    #[test]
    fn rejects_upstream_malformed_rule_set_corpus() {
        let one = encode_uvarint(1);
        let huge = encode_uvarint(1_u64 << 40);
        let default_rule = [0_u8];
        let ip_range_count = (1_u64 << 40).to_be_bytes();
        let mut deep_logical_nesting = one.clone();
        deep_logical_nesting
            .extend(std::iter::repeat_n([1_u8, 0, 1], 10_000).flatten());

        let cases = [
            ("huge_rule_count", huge.clone()),
            (
                "huge_string_count",
                append(&[&one, &default_rule, &[ITEM_DOMAIN_KEYWORD], &huge]),
            ),
            (
                "huge_string_length",
                append(&[
                    &one,
                    &default_rule,
                    &[ITEM_DOMAIN_KEYWORD],
                    &one,
                    &huge,
                ]),
            ),
            (
                "huge_uint16_count",
                append(&[&one, &default_rule, &[ITEM_QUERY_TYPE], &huge]),
            ),
            (
                "huge_ip_range_count",
                append(&[
                    &one,
                    &default_rule,
                    &[ITEM_IP_CIDR, 1],
                    &ip_range_count,
                ]),
            ),
            (
                "bad_ip_range_address_length",
                append(&[
                    &one,
                    &default_rule,
                    &[ITEM_IP_CIDR, 1],
                    &1_u64.to_be_bytes(),
                    &encode_uvarint(99),
                ]),
            ),
            (
                "huge_prefix_address_length",
                append(&[
                    &one,
                    &default_rule,
                    &[ITEM_DEFAULT_INTERFACE_ADDRESS],
                    &one,
                    &huge,
                ]),
            ),
            (
                "empty_domain_matcher",
                append(&[&one, &default_rule, &[ITEM_DOMAIN, 0], &[0, 0, 0]]),
            ),
            (
                "huge_domain_matcher_bitmap",
                append(&[&one, &default_rule, &[ITEM_DOMAIN, 0], &huge]),
            ),
            ("deep_logical_nesting", deep_logical_nesting),
        ];

        for (name, body) in cases {
            assert!(read(&craft_rule_set(&body)).is_err(), "{name}");
        }
    }

    #[test]
    fn splits_ip_ranges_into_minimal_prefixes() {
        assert_eq!(
            range_to_prefixes(
                "10.0.0.0".parse().unwrap(),
                "10.0.0.255".parse().unwrap()
            )
            .unwrap(),
            ["10.0.0.0/24"]
        );
        assert_eq!(
            range_to_prefixes(
                "::".parse().unwrap(),
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
            )
            .unwrap(),
            ["::/0"]
        );
    }

    #[test]
    fn reads_v5_fixture_emitted_by_upstream_go_sing_box() {
        let content = STANDARD.decode(GO_SRS_V5).unwrap();
        let rules = read(&content).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["query_type"], serde_json::json!(["A", "AAAA"]));
        assert_eq!(rules[0]["domain"], serde_json::json!(["exact.example"]));
        assert_eq!(
            rules[0]["domain_suffix"],
            serde_json::json!([".children.only", "example.cn"])
        );
        assert_eq!(
            rules[0]["ip_cidr"],
            serde_json::json!(["10.0.0.0/8", "2001:db8::/32"])
        );
        assert_eq!(
            rules[0]["network_interface_address"]["wifi"],
            serde_json::json!(["172.16.0.0/12"])
        );
        assert_eq!(rules[0]["invert"], true);
        assert_eq!(rules[1]["type"], "logical");
        assert_eq!(rules[1]["mode"], "or");
        assert_eq!(rules[1]["rules"].as_array().unwrap().len(), 2);
        let compiled = super::super::compile_headless_rules(&rules).unwrap();
        let domain = super::super::Metadata {
            destination: Some(super::super::SocksAddr::new(
                "logical.example",
                443,
            )),
            ..super::super::Metadata::default()
        };
        assert!(compiled[1].matches_with_ip_source(&domain, false));
        let address = super::super::Metadata {
            destination: Some(super::super::SocksAddr::new("203.0.113.4", 443)),
            ..super::super::Metadata::default()
        };
        assert!(compiled[1].matches_with_ip_source(&address, false));

        let runtime = read_runtime(&content).unwrap();
        let RuntimeRule::Default(rule) = &runtime[0] else {
            panic!("Go fixture must contain a compact domain matcher");
        };
        let Some(domain) = &rule.domain else {
            panic!("Go fixture must contain a compact domain matcher");
        };
        assert!(domain.matches_domain("exact.example"));
        assert!(!domain.matches_domain("sub.exact.example"));
        assert!(domain.matches_domain("example.cn"));
        assert!(domain.matches_domain("www.example.cn"));
        assert!(!domain.matches_domain("children.only"));
        assert!(domain.matches_domain("www.children.only"));
    }

    #[test]
    fn writes_rule_sets_that_round_trip_all_binary_versions() {
        let rules = serde_json::json!([
            {
                "query_type": ["A", 65000],
                "domain": "exact.example",
                "domain_suffix": ["example.org", ".children.example"],
                "source_ip_cidr": "192.168.0.0/16",
                "ip_cidr": ["10.0.0.0/8", "2001:db8::/32"],
                "port": [80, 443],
                "network_type": ["wifi", "ethernet"],
                "network_interface_address": {
                    "wifi": "172.16.0.0/12"
                },
                "default_interface_address": "100.64.0.0/10",
                "package_name_regex": "^org\\."
            },
            {
                "type": "logical",
                "mode": "or",
                "rules": [
                    {"domain_keyword": "internal"},
                    {"ip_cidr": "203.0.113.0/24"}
                ],
                "invert": true
            }
        ]);
        let rules = rules.as_array().unwrap();
        let content = write(rules, 5).unwrap();
        let (version, recovered) = read_with_version(&content).unwrap();
        assert_eq!(version, 5);
        assert_eq!(recovered[0]["query_type"], serde_json::json!(["A", 65000]));
        assert_eq!(
            recovered[0]["domain"],
            serde_json::json!(["exact.example"])
        );
        assert_eq!(
            recovered[0]["domain_suffix"],
            serde_json::json!([".children.example", "example.org"])
        );
        assert_eq!(recovered[0]["ip_cidr"], rules[0]["ip_cidr"]);
        assert_eq!(
            recovered[0]["network_interface_address"]["wifi"],
            serde_json::json!(["172.16.0.0/12"])
        );
        assert_eq!(recovered[1]["type"], "logical");
        assert_eq!(recovered[1]["invert"], true);
    }

    #[test]
    fn selects_the_oldest_binary_version_that_preserves_features() {
        let simple = serde_json::json!([{"domain": "example.org"}]);
        assert_eq!(downgrade_version(simple.as_array().unwrap(), 5), 2);
        let network = serde_json::json!([{"network_type": "wifi"}]);
        assert_eq!(downgrade_version(network.as_array().unwrap(), 5), 3);
        let interface =
            serde_json::json!([{"default_interface_address": "10.0.0.0/8"}]);
        assert_eq!(downgrade_version(interface.as_array().unwrap(), 5), 4);
        let package = serde_json::json!([{"package_name_regex": "org"}]);
        assert_eq!(downgrade_version(package.as_array().unwrap(), 5), 5);
    }
}
