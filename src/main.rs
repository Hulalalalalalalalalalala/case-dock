use std::env;
use std::fmt::Write as _;
use std::process::ExitCode;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Domain-separation prefix for the signed message encoding (format version 1).
const MAGIC: &[u8] = b"authnote-sign-v1";

const USAGE: &str =
    "Usage: authnote --version | authnote sign --key HEX --key-id ID --key-version N [--field TEXT]...";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--version") && args.len() == 1 {
        println!("authnote 0.1.0");
        ExitCode::SUCCESS
    } else if args.first().map(String::as_str) == Some("sign") {
        sign(&args[1..])
    } else {
        eprintln!("{USAGE}");
        ExitCode::from(2)
    }
}

fn sign(args: &[String]) -> ExitCode {
    let mut key_hex: Option<String> = None;
    let mut key_id: Option<String> = None;
    let mut version_raw: Option<String> = None;
    let mut fields: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let opt = args[i].as_str();
        match opt {
            "--key" | "--key-id" | "--key-version" | "--field" => {
                let Some(value) = args.get(i + 1) else {
                    eprintln!("error: option {opt} requires a value");
                    return ExitCode::from(2);
                };
                let slot = match opt {
                    "--key" => &mut key_hex,
                    "--key-id" => &mut key_id,
                    "--key-version" => &mut version_raw,
                    _ => {
                        fields.push(value.clone());
                        i += 2;
                        continue;
                    }
                };
                if slot.is_some() {
                    eprintln!("error: option {opt} must be given exactly once");
                    return ExitCode::from(2);
                }
                *slot = Some(value.clone());
                i += 2;
            }
            other if other.starts_with('-') => {
                eprintln!("error: unknown option '{other}'");
                return ExitCode::from(2);
            }
            other => {
                eprintln!("error: unexpected argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    // Never echo the key material (or the rejected key string) in errors.
    let Some(key_hex) = key_hex else {
        eprintln!("error: missing required option --key");
        return ExitCode::from(2);
    };
    let Some(key) = decode_hex(&key_hex) else {
        eprintln!("error: --key must be a non-empty, even-length hexadecimal string");
        return ExitCode::from(2);
    };
    let Some(key_id) = key_id else {
        eprintln!("error: missing required option --key-id");
        return ExitCode::from(2);
    };
    if key_id.is_empty() {
        eprintln!("error: --key-id must not be empty");
        return ExitCode::from(2);
    }
    let Some(version_raw) = version_raw else {
        eprintln!("error: missing required option --key-version");
        return ExitCode::from(2);
    };
    let Some(key_version) = parse_version(&version_raw) else {
        eprintln!("error: --key-version must be a decimal integer between 1 and 4294967295");
        return ExitCode::from(2);
    };

    let message = encode_message(&key_id, key_version, &fields);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(&message);
    let tag = mac.finalize().into_bytes();

    let mut tag_hex = String::with_capacity(tag.len() * 2);
    for byte in tag {
        let _ = write!(tag_hex, "{byte:02x}");
    }

    let mut json = String::from("{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"");
    json.push_str(&json_escape(&key_id));
    let _ = write!(json, "\",\"key_version\":{key_version},\"fields\":[");
    for (idx, field) in fields.iter().enumerate() {
        if idx > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(&json_escape(field));
        json.push('"');
    }
    let _ = write!(json, "],\"tag\":\"{tag_hex}\"}}");
    println!("{json}");
    ExitCode::SUCCESS
}

/// Canonical byte encoding of the authenticated content.
///
/// Layout (all integers are unsigned 32-bit big-endian):
///   MAGIC (16 bytes, "authnote-sign-v1")
///   key_id length || key_id (UTF-8 bytes)
///   key_version
///   field count
///   for each field, in order: field length || field (UTF-8 bytes)
///
/// Length-prefixing every variable-length item makes the encoding
/// unambiguous: distinct (key_id, version, fields) triples never produce
/// the same byte string.
fn encode_message(key_id: &str, key_version: u32, fields: &[String]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(MAGIC);
    msg.extend_from_slice(&(key_id.len() as u32).to_be_bytes());
    msg.extend_from_slice(key_id.as_bytes());
    msg.extend_from_slice(&key_version.to_be_bytes());
    msg.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for field in fields {
        msg.extend_from_slice(&(field.len() as u32).to_be_bytes());
        msg.extend_from_slice(field.as_bytes());
    }
    msg
}

/// Decodes a non-empty, even-length hexadecimal string (either case).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Parses a decimal integer in the range 1..=4294967295.
fn parse_version(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u64 = s.parse().ok()?;
    if (1..=u64::from(u32::MAX)).contains(&value) {
        Some(value as u32)
    } else {
        None
    }
}

/// Escapes a string for inclusion in a JSON record. Non-ASCII characters
/// are emitted as-is (the record is UTF-8); only the characters JSON
/// requires to be escaped are escaped.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_accepts_both_cases() {
        assert_eq!(decode_hex("0aFF"), Some(vec![0x0a, 0xff]));
        assert_eq!(decode_hex(""), None);
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("中文"), None);
    }

    #[test]
    fn version_bounds() {
        assert_eq!(parse_version("1"), Some(1));
        assert_eq!(parse_version("4294967295"), Some(u32::MAX));
        assert_eq!(parse_version("0"), None);
        assert_eq!(parse_version("4294967296"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("-1"), None);
        assert_eq!(parse_version("1.0"), None);
        assert_eq!(parse_version(" 1"), None);
    }

    #[test]
    fn encoding_binds_field_boundaries() {
        let a = encode_message("id", 1, &["ab".into(), "c".into()]);
        let b = encode_message("id", 1, &["a".into(), "bc".into()]);
        assert_ne!(a, b);
    }

    #[test]
    fn encoding_distinguishes_zero_fields_from_one_empty_field() {
        let a = encode_message("id", 1, &[]);
        let b = encode_message("id", 1, &[String::new()]);
        assert_ne!(a, b);
    }

    #[test]
    fn encoding_binds_key_id_and_version() {
        let base = encode_message("id", 1, &["x".into()]);
        assert_ne!(base, encode_message("id2", 1, &["x".into()]));
        assert_ne!(base, encode_message("id", 2, &["x".into()]));
    }
}
