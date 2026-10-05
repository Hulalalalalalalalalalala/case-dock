use std::env;
use std::process::ExitCode;

use hmac::{
    Hmac, Mac,
    digest::KeyInit,
};
use sha2::Sha256;

const FORMAT_VERSION: u32 = 1;
const ALGORITHM: &str = "HMAC-SHA256";
/// Domain separator that also records the format version, so tags computed
/// by different versions of the encoding can never collide.
const DOMAIN_SEPARATOR: &[u8] = b"authnote-sign-v1";

fn main() -> ExitCode {
    let args: Vec<String> = match decode_args() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("authnote: {msg}");
            return ExitCode::from(2);
        }
    };
    match args.first().map(String::as_str) {
        Some("--version") if args.len() == 1 => {
            println!("authnote 0.1.0");
            ExitCode::SUCCESS
        }
        Some("sign") => sign(&args[1..]),
        _ => {
            eprintln!("Usage: authnote --version");
            eprintln!(
                "       authnote sign --key HEX --key-id ID --key-version N [--field TEXT]..."
            );
            ExitCode::from(2)
        }
    }
}

/// Decode the process arguments (excluding the program name) as UTF-8 text.
///
/// `env::args()` panics on arguments that are not valid UTF-8; decoding via
/// `args_os()` lets us report the problem as an ordinary usage error instead.
/// The raw bytes are never printed: the message only states *that* an
/// argument could not be decoded, not what it contained.
fn decode_args() -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (index, arg) in env::args_os().skip(1).enumerate() {
        match arg.into_string() {
            Ok(s) => out.push(s),
            Err(_) => {
                return Err(format!(
                    "argument {} is not valid UTF-8 text; all arguments must be decodable text",
                    index + 1
                ));
            }
        }
    }
    Ok(out)
}

struct SignOptions {
    key: String,
    key_id: String,
    key_version: String,
    fields: Vec<String>,
}

fn sign(args: &[String]) -> ExitCode {
    match parse_sign_args(args).and_then(validate_sign_args) {
        Ok(opts) => {
            let key_bytes = decode_hex(&opts.key).expect("key was validated as hex");
            let key_version: u32 = opts.key_version.parse().expect("version was validated");
            let message = encode_message(&opts.key_id, key_version, &opts.fields);
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key_bytes)
                .expect("HMAC accepts keys of any length");
            mac.update(&message);
            let tag = mac.finalize().into_bytes();

            let fields_json = opts
                .fields
                .iter()
                .map(|f| format!("\"{}\"", json_escape(f)))
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{{\"format\":{FORMAT_VERSION},\"algorithm\":\"{ALGORITHM}\",\"key_id\":\"{}\",\"key_version\":{},\"fields\":[{}],\"tag\":\"{}\"}}",
                json_escape(&opts.key_id),
                key_version,
                fields_json,
                hex_encode(&tag),
            );
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("authnote sign: {msg}");
            ExitCode::from(2)
        }
    }
}

fn parse_sign_args(args: &[String]) -> Result<SignOptions, String> {
    let mut key: Option<String> = None;
    let mut key_id: Option<String> = None;
    let mut key_version: Option<String> = None;
    let mut fields: Vec<String> = Vec::new();

    let set_once = |slot: &mut Option<String>, name: &str, value: String| -> Result<(), String> {
        if slot.is_some() {
            return Err(format!("option {name} must be given exactly once"));
        }
        *slot = Some(value);
        Ok(())
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        // Support both "--opt value" and "--opt=value" forms.
        let (name, inline_value) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let take_value = |i: &mut usize| -> Result<String, String> {
            if let Some(v) = inline_value {
                return Ok(v);
            }
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("option {name} requires a value"))
        };
        match name {
            "--key" => {
                let v = take_value(&mut i)?;
                set_once(&mut key, "--key", v)?;
            }
            "--key-id" => {
                let v = take_value(&mut i)?;
                set_once(&mut key_id, "--key-id", v)?;
            }
            "--key-version" => {
                let v = take_value(&mut i)?;
                set_once(&mut key_version, "--key-version", v)?;
            }
            "--field" => {
                let v = take_value(&mut i)?;
                fields.push(v);
            }
            _ => {
                // Never echo the unrecognized argument itself: it may be a
                // misplaced secret (e.g. a key value whose option name was
                // mistyped or whose value was consumed by another option).
                return Err(
                    "unrecognized option or argument (known options: --key, --key-id, --key-version, --field)"
                        .to_string(),
                );
            }
        }
        i += 1;
    }

    let key = key.ok_or("missing required option --key")?;
    let key_id = key_id.ok_or("missing required option --key-id")?;
    let key_version = key_version.ok_or("missing required option --key-version")?;
    Ok(SignOptions {
        key,
        key_id,
        key_version,
        fields,
    })
}

fn validate_sign_args(opts: SignOptions) -> Result<SignOptions, String> {
    // Never echo the key back in error messages.
    if opts.key.is_empty()
        || opts.key.len() % 2 != 0
        || !opts.key.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("--key must be a non-empty, even-length hexadecimal string".to_string());
    }
    if opts.key_id.is_empty() {
        return Err("--key-id must not be empty".to_string());
    }
    let valid_version = !opts.key_version.is_empty()
        && opts.key_version.bytes().all(|b| b.is_ascii_digit())
        && opts
            .key_version
            .parse::<u64>()
            .is_ok_and(|v| (1..=u32::MAX as u64).contains(&v));
    if !valid_version {
        return Err("--key-version must be a decimal integer between 1 and 4294967295".to_string());
    }
    Ok(opts)
}

/// Canonical byte encoding of the authenticated content.
///
/// Layout (all integers big-endian, all text UTF-8, no trimming or escaping):
///   DOMAIN_SEPARATOR ("authnote-sign-v1", 16 ASCII bytes)
///   u64 length of key-id, then key-id bytes
///   u32 key version
///   u64 field count
///   for each field in order: u64 length of field, then field bytes
///
/// Length prefixes make field boundaries unambiguous: ["ab","c"] and
/// ["a","bc"] encode differently, as do zero fields and one empty field.
fn encode_message(key_id: &str, key_version: u32, fields: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN_SEPARATOR);
    push_len_prefixed(&mut out, key_id.as_bytes());
    out.extend_from_slice(&key_version.to_be_bytes());
    out.extend_from_slice(&(fields.len() as u64).to_be_bytes());
    for field in fields {
        push_len_prefixed(&mut out, field.as_bytes());
    }
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_tag(key_hex: &str, key_id: &str, version: u32, fields: &[&str]) -> String {
        let key = decode_hex(key_hex).unwrap();
        let owned: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
        let msg = encode_message(key_id, version, &owned);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(&msg);
        hex_encode(&mac.finalize().into_bytes())
    }

    #[test]
    // RFC 4231 test case 1: HMAC-SHA256 with key 0x0b*20, data "Hi There".
    fn hmac_matches_rfc4231() {
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(b"Hi There");
        assert_eq!(
            hex_encode(&mac.finalize().into_bytes()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        assert_ne!(sign_tag("00ff", "id", 1, &["ab", "c"]), sign_tag("00ff", "id", 1, &["a", "bc"]));
        assert_ne!(sign_tag("00ff", "id", 1, &[]), sign_tag("00ff", "id", 1, &[""]));
    }

    #[test]
    fn metadata_is_bound() {
        let base = sign_tag("00ff", "id", 1, &["x"]);
        assert_ne!(base, sign_tag("00ff", "id2", 1, &["x"]));
        assert_ne!(base, sign_tag("00ff", "id", 2, &["x"]));
        assert_ne!(base, sign_tag("ff00", "id", 1, &["x"]));
        assert_eq!(base, sign_tag("00FF", "id", 1, &["x"])); // hex case-insensitive
    }

    #[test]
    fn rejects_bad_input() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(parse_sign_args(&args(&[])).is_err()); // missing required
        assert!(parse_sign_args(&args(&["--key"])).is_err()); // missing value
        assert!(parse_sign_args(&args(&["--nope", "x"])).is_err()); // unknown
        assert!(parse_sign_args(&args(&["--key", "aa", "--key", "bb", "--key-id", "i", "--key-version", "1"])).is_err()); // duplicate
        let ok = |k: &str, id: &str, v: &str| {
            parse_sign_args(&args(&["--key", k, "--key-id", id, "--key-version", v]))
                .and_then(validate_sign_args)
        };
        assert!(ok("", "i", "1").is_err());
        assert!(ok("abc", "i", "1").is_err()); // odd length
        assert!(ok("zz", "i", "1").is_err()); // not hex
        assert!(ok("aa", "", "1").is_err()); // empty key-id
        assert!(ok("aa", "i", "0").is_err());
        assert!(ok("aa", "i", "4294967296").is_err());
        assert!(ok("aa", "i", "1.5").is_err());
        assert!(ok("aa", "i", "4294967295").is_ok());
        assert!(ok("AAbb", "i", "007").is_ok());
    }
}
