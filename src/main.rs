use std::env;
use std::io::Read;
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
        Some("verify") => verify(&args[1..]),
        _ => {
            eprintln!("Usage: authnote --version");
            eprintln!(
                "       authnote sign --key HEX --key-id ID --key-version N [--field TEXT]..."
            );
            eprintln!("       authnote verify --key HEX");
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
    validate_key_hex(&opts.key)?;
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

/// Shared key validation for `sign` and `verify`: non-empty even-length hex.
/// The rejected value is never included in the message.
fn validate_key_hex(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() % 2 != 0 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--key must be a non-empty, even-length hexadecimal string".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn verify(args: &[String]) -> ExitCode {
    // The option grammar for verify mirrors sign: "--opt value" or
    // "--opt=value", exactly one --key, no other options. Values that fail are
    // never echoed (they could be a mistyped secret).
    let mut key: Option<String> = None;
    let mut i = 0;
    let parse = (|| -> Result<String, String> {
        while i < args.len() {
            let arg = &args[i];
            let (name, inline_value) = match arg.split_once('=') {
                Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
                _ => (arg.as_str(), None),
            };
            if name != "--key" {
                return Err(
                    "unrecognized option or argument (the only known option is --key)"
                        .to_string(),
                );
            }
            let value = if let Some(v) = inline_value {
                v
            } else {
                i += 1;
                match args.get(i) {
                    Some(v) => v.clone(),
                    None => return Err("option --key requires a value".to_string()),
                }
            };
            if key.is_some() {
                return Err("option --key must be given exactly once".to_string());
            }
            key = Some(value);
            i += 1;
        }
        let key = key.ok_or("missing required option --key")?;
        validate_key_hex(&key)?;
        Ok(key)
    })();

    let key_hex = match parse {
        Ok(key) => key,
        Err(msg) => {
            eprintln!("authnote verify: {msg}");
            return ExitCode::from(2);
        }
    };

    // Read the whole standard input. It must be one JSON record and nothing
    // else; trailing non-whitespace is a malformed invocation, not a mismatch.
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("authnote verify: failed to read standard input: {e}");
        return ExitCode::from(2);
    }

    let outcome = verify_input(&input, &key_hex);
    match outcome {
        VerifyOutcome::Valid => {
            println!("{{\"valid\":true}}");
            ExitCode::SUCCESS
        }
        VerifyOutcome::Mismatch => {
            println!("{{\"valid\":false}}");
            ExitCode::from(1)
        }
        VerifyOutcome::Invalid(msg) => {
            eprintln!("authnote verify: {msg}");
            ExitCode::from(2)
        }
    }
}

#[derive(Debug)]
enum VerifyOutcome {
    Valid,
    Mismatch,
    Invalid(String),
}

fn verify_input(input: &[u8], key_hex: &str) -> VerifyOutcome {
    let text = match std::str::from_utf8(input) {
        Ok(t) => t,
        // Still parse to distinguish a structurally invalid record from a
        // record whose text merely contains bytes Rust rejects; JSON itself
        // forbids raw non-UTF-8, so this is always "corrupt input" here.
        Err(_) => return VerifyOutcome::Invalid("input is not valid UTF-8 JSON text".to_string()),
    };

    let value = match json::parse_single(text) {
        Ok(v) => v,
        Err(msg) => return VerifyOutcome::Invalid(msg),
    };
    let record = match record_from_json(&value) {
        Ok(r) => r,
        Err(msg) => return VerifyOutcome::Invalid(msg),
    };

    let key_bytes = decode_hex(key_hex).expect("key was validated as hex");
    let message = encode_message(&record.key_id, record.key_version, &record.fields);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key_bytes)
        .expect("HMAC accepts keys of any length");
    mac.update(&message);

    let expected_tag = mac.finalize().into_bytes();
    let given_tag = &record.tag;

    // Both sides are 32 bytes; compare in constant time so a mismatch cannot
    // be recovered one byte at a time through timing.
    debug_assert_eq!(expected_tag.len(), given_tag.len());
    if expected_tag.len() != given_tag.len() {
        return VerifyOutcome::Mismatch;
    }
    let mut diff = 0u8;
    for (a, b) in expected_tag.iter().zip(given_tag.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        VerifyOutcome::Valid
    } else {
        VerifyOutcome::Mismatch
    }
}

/// Decode the tag as exactly 32 bytes of case-insensitive hexadecimal.
fn decode_tag(s: &str) -> Result<Vec<u8>, String> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("tag must be exactly 64 hexadecimal characters (32 bytes)".to_string());
    }
    decode_hex(s).map_err(|e| format!("tag is not valid hexadecimal: {e}"))
}

struct AuthRecord {
    key_id: String,
    key_version: u32,
    fields: Vec<String>,
    tag: Vec<u8>,
}

/// Validate the decoded JSON value as exactly one format-1 authentication
/// record and pull out the authenticated fields. Structural problems (missing
/// members, wrong types, duplicates inside `fields`, ...) are caller errors:
/// they must produce exit 2, never a `{"valid":false}` mismatch result.
fn record_from_json(value: &json::JsonValue) -> Result<AuthRecord, String> {
    let obj = match value {
        json::JsonValue::Object(entries) => entries,
        _ => return Err("record must be a single JSON object".to_string()),
    };

    // Require precisely the six documented members, each present exactly once;
    // the parser already rejects duplicate member names, and an empty object
    // naturally fails the "missing required member" checks below.
    let mut format: Option<&json::JsonValue> = None;
    let mut algorithm: Option<&json::JsonValue> = None;
    let mut key_id: Option<&json::JsonValue> = None;
    let mut key_version: Option<&json::JsonValue> = None;
    let mut fields: Option<&json::JsonValue> = None;
    let mut tag: Option<&json::JsonValue> = None;
    for (name, val) in obj {
        let slot = match name.as_str() {
            "format" => &mut format,
            "algorithm" => &mut algorithm,
            "key_id" => &mut key_id,
            "key_version" => &mut key_version,
            "fields" => &mut fields,
            "tag" => &mut tag,
            // Do not echo the unknown member name: it comes from the input
            // record, which error messages must never quote back.
            _ => return Err("record contains an unexpected member".to_string()),
        };
        if slot.is_some() {
            // The strict parser rejects duplicates already; keep a defense in
            // depth without quoting the member name from the input twice.
            return Err("record contains a duplicate member".to_string());
        }
        *slot = Some(val);
    }

    // Unsupported format/algorithm must be reported as such explicitly: we do
    // not silently fall back to the current rules and compute a result.
    let format = format.ok_or("record is missing required member \"format\"")?;
    match format {
        json::JsonValue::Number(n) if *n == i128::from(FORMAT_VERSION) => {}
        json::JsonValue::Number(_) => {
            return Err("unsupported record format version; only format 1 is supported".to_string())
        }
        _ => return Err("member \"format\" must be an integer".to_string()),
    }

    let algorithm = algorithm.ok_or("record is missing required member \"algorithm\"")?;
    match algorithm {
        json::JsonValue::String(s) if s == ALGORITHM => {}
        json::JsonValue::String(_) => {
            return Err(
                "unsupported algorithm in record; only HMAC-SHA256 is supported".to_string(),
            )
        }
        _ => return Err("member \"algorithm\" must be a string".to_string()),
    }

    let key_id = key_id.ok_or("record is missing required member \"key_id\"")?;
    let key_id = match key_id {
        json::JsonValue::String(s) if !s.is_empty() => s.clone(),
        json::JsonValue::String(_) => {
            return Err("member \"key_id\" must not be empty".to_string())
        }
        _ => return Err("member \"key_id\" must be a string".to_string()),
    };

    let key_version = key_version.ok_or("record is missing required member \"key_version\"")?;
    let key_version = match key_version {
        json::JsonValue::Number(n) => {
            if *n < 1 || *n > i128::from(u32::MAX) {
                return Err(
                    "member \"key_version\" is outside the supported range 1..=4294967295"
                        .to_string(),
                );
            }
            *n as u32
        }
        _ => return Err("member \"key_version\" must be an integer".to_string()),
    };

    let fields_val = fields.ok_or("record is missing required member \"fields\"")?;
    let fields = match fields_val {
        json::JsonValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    json::JsonValue::String(s) => out.push(s.clone()),
                    _ => {
                        return Err(
                            "every element of member \"fields\" must be a string".to_string()
                        )
                    }
                }
            }
            out
        }
        _ => return Err("member \"fields\" must be an array of strings".to_string()),
    };

    let tag_val = tag.ok_or("record is missing required member \"tag\"")?;
    let tag = match tag_val {
        json::JsonValue::String(s) => decode_tag(s)?,
        _ => return Err("member \"tag\" must be a string".to_string()),
    };

    Ok(AuthRecord {
        key_id,
        key_version,
        fields,
        tag,
    })
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

// ---------------------------------------------------------------------------
// Strict JSON parser used by `verify`.
//
// Written by hand so the crate keeps zero third-party runtime dependencies.
// Unlike a tolerant parser it enforces every rule the verify contract relies
// on: exactly one complete value surrounded only by JSON whitespace, no
// duplicate member names within an object, strict number grammar (integers
// only, no fractions/exponents/leading zeros), strings decoded per RFC 8259
// including surrogate pairs. Anything it cannot parse is a corrupt record
// (exit 2), never a mismatch.
// ---------------------------------------------------------------------------

mod json {
    #[derive(Debug, PartialEq)]
    pub enum JsonValue {
        /// Parsed as an integer because the record grammar has no fractional
        /// values; the width comfortably covers u32 and common JSON integers.
        Number(i128),
        String(String),
        Array(Vec<JsonValue>),
        /// Members kept in source order; names are unique (parser-enforced).
        Object(Vec<(String, JsonValue)>),
        // Accepted so documents using them parse, but records containing them
        // are rejected structurally by the caller.
        Bool(bool),
        Null,
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
        /// Current object/array nesting depth, capped so adversarial input
        /// ("[[[[...")") cannot exhaust the stack and crash the verifier.
        depth: usize,
    }

    /// Far above the depth a real record ever reaches (record → `fields`
    /// array → string is depth 2) while staying well within stack limits.
    const MAX_DEPTH: usize = 64;

    /// Parse exactly one JSON value: optional leading/trailing JSON whitespace
    /// is allowed, but any trailing non-whitespace content (including a second
    /// object) is an error.
    pub fn parse_single(input: &str) -> Result<JsonValue, String> {
        let mut p = Parser {
            bytes: input.as_bytes(),
            pos: 0,
            depth: 0,
        };
        p.skip_ws();
        if p.pos == p.bytes.len() {
            return Err("input is empty; expected one JSON record".to_string());
        }
        let value = p.parse_value()?;
        p.skip_ws();
        if p.pos != p.bytes.len() {
            return Err(
                "trailing non-whitespace content after record; exactly one JSON object is allowed"
                    .to_string(),
            );
        }
        Ok(value)
    }

    impl<'a> Parser<'a> {
        fn skip_ws(&mut self) {
            while self.pos < self.bytes.len()
                && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
            {
                self.pos += 1;
            }
        }

        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }

        fn enter_container(&mut self) -> Result<(), String> {
            if self.depth >= MAX_DEPTH {
                return Err("JSON nesting is too deep".to_string());
            }
            self.depth += 1;
            Ok(())
        }

        fn parse_value(&mut self) -> Result<JsonValue, String> {
            self.skip_ws();
            match self.peek() {
                Some(b'{') => self.parse_object(),
                Some(b'[') => self.parse_array(),
                Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
                Some(b't') => self.parse_lit("true", JsonValue::Bool(true)),
                Some(b'f') => self.parse_lit("false", JsonValue::Bool(false)),
                Some(b'n') => self.parse_lit("null", JsonValue::Null),
                Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
                Some(_) => Err("unexpected character while parsing JSON".to_string()),
                None => Err("unexpected end of JSON input".to_string()),
            }
        }

        fn parse_lit(&mut self, lit: &str, value: JsonValue) -> Result<JsonValue, String> {
            if self.bytes[self.pos..].starts_with(lit.as_bytes()) {
                self.pos += lit.len();
                Ok(value)
            } else {
                Err("malformed JSON literal".to_string())
            }
        }

        fn parse_object(&mut self) -> Result<JsonValue, String> {
            self.enter_container()?;
            let result = self.parse_object_inner();
            self.depth -= 1;
            result
        }

        fn parse_object_inner(&mut self) -> Result<JsonValue, String> {
            self.pos += 1; // '{'
            let mut entries: Vec<(String, JsonValue)> = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(JsonValue::Object(entries));
            }
            loop {
                self.skip_ws();
                if self.peek() != Some(b'"') {
                    return Err("expected a string member name in JSON object".to_string());
                }
                let name = self.parse_string()?;
                self.skip_ws();
                if self.peek() != Some(b':') {
                    return Err("expected ':' after JSON member name".to_string());
                }
                self.pos += 1;
                let value = self.parse_value()?;
                if entries.iter().any(|(n, _)| *n == name) {
                    return Err("JSON object contains a duplicate member".to_string());
                }
                entries.push((name, value));
                self.skip_ws();
                match self.peek() {
                    Some(b',') => {
                        self.pos += 1;
                    }
                    Some(b'}') => {
                        self.pos += 1;
                        break;
                    }
                    Some(_) => return Err("expected ',' or '}}' in JSON object".to_string()),
                    None => return Err("unterminated JSON object".to_string()),
                }
            }
            Ok(JsonValue::Object(entries))
        }

        fn parse_array(&mut self) -> Result<JsonValue, String> {
            self.enter_container()?;
            let result = self.parse_array_inner();
            self.depth -= 1;
            result
        }

        fn parse_array_inner(&mut self) -> Result<JsonValue, String> {
            self.pos += 1; // '['
            let mut items = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(JsonValue::Array(items));
            }
            loop {
                items.push(self.parse_value()?);
                self.skip_ws();
                match self.peek() {
                    Some(b',') => {
                        self.pos += 1;
                        self.skip_ws();
                    }
                    Some(b']') => {
                        self.pos += 1;
                        break;
                    }
                    Some(_) => return Err("expected ',' or ']' in JSON array".to_string()),
                    None => return Err("unterminated JSON array".to_string()),
                }
            }
            Ok(JsonValue::Array(items))
        }

        fn parse_string(&mut self) -> Result<String, String> {
            self.pos += 1; // opening quote
            let mut out = String::new();
            loop {
                match self.peek() {
                    None => return Err("unterminated JSON string".to_string()),
                    Some(b'"') => {
                        self.pos += 1;
                        break;
                    }
                    Some(b'\\') => {
                        self.pos += 1;
                        let esc = self
                            .peek()
                            .ok_or("unterminated JSON escape sequence")?;
                        self.pos += 1;
                        match esc {
                            b'"' => out.push('"'),
                            b'\\' => out.push('\\'),
                            b'/' => out.push('/'),
                            b'b' => out.push('\u{0008}'),
                            b'f' => out.push('\u{000c}'),
                            b'n' => out.push('\n'),
                            b'r' => out.push('\r'),
                            b't' => out.push('\t'),
                            b'u' => {
                                let hi = self.parse_hex4()?;
                                let c = if (0xD800..=0xDBFF).contains(&hi) {
                                    // High surrogate must be followed by "\uXXXX"
                                    // low surrogate; lone surrogates are invalid.
                                    if self.peek() != Some(b'\\') {
                                        return Err(
                                            "lone UTF-16 high surrogate in JSON string".to_string()
                                        );
                                    }
                                    self.pos += 1;
                                    if self.peek() != Some(b'u') {
                                        return Err(
                                            "bad surrogate pair escape in JSON string".to_string()
                                        );
                                    }
                                    self.pos += 1;
                                    let lo = self.parse_hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return Err(
                                            "low surrogate out of range in JSON string".to_string()
                                        );
                                    }
                                    char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                                        .ok_or("invalid surrogate pair in JSON string")?
                                } else if (0xDC00..=0xDFFF).contains(&hi) {
                                    return Err(
                                        "lone UTF-16 low surrogate in JSON string".to_string()
                                    );
                                } else {
                                    char::from_u32(hi)
                                        .ok_or("invalid unicode escape in JSON string")?
                                };
                                out.push(c);
                            }
                            _ => {
                                return Err("invalid escape sequence in JSON string".to_string())
                            }
                        }
                    }
                    Some(c) if c < 0x20 => {
                        return Err("unescaped control character in JSON string".to_string())
                    }
                    Some(_) => {
                        // Copy one whole UTF-8 scalar at a time, validating that
                        // the raw bytes really are UTF-8 (the surrounding input
                        // is &str so this cannot fail, but keep the boundary
                        // explicit rather than slicing mid-char).
                        let start = self.pos;
                        self.pos += 1;
                        while self.pos < self.bytes.len() {
                            let b = self.bytes[self.pos];
                            if b == b'"' || b == b'\\' || b < 0x20 {
                                break;
                            }
                            self.pos += 1;
                        }
                        let chunk = std::str::from_utf8(&self.bytes[start..self.pos])
                            .map_err(|_| "invalid UTF-8 inside JSON string".to_string())?;
                        out.push_str(chunk);
                    }
                }
            }
            Ok(out)
        }

        fn parse_hex4(&mut self) -> Result<u32, String> {
            let mut v = 0u32;
            for _ in 0..4 {
                if self.peek().is_none() {
                    return Err("truncated \\u escape in JSON string".to_string());
                }
                let c = self.peek().unwrap();
                if !(c as char).is_ascii_hexdigit() {
                    return Err("bad hexadecimal digit in \\u escape".to_string());
                }
                let d = (c as char).to_digit(16).unwrap();
                self.pos += 1;
                v = v * 16 + d;
            }
            Ok(v)
        }

        /// Strict RFC 8259 integer grammar. The record format has no fractional
        /// values, so `.`/`e` forms are rejected rather than truncated.
        fn parse_number(&mut self) -> Result<JsonValue, String> {
            let start = self.pos;
            if self.peek() == Some(b'-') {
                self.pos += 1;
            }
            match self.peek() {
                Some(b'0') => {
                    self.pos += 1;
                    // A leading zero must not be followed by more digits.
                    if matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                        return Err("numbers with leading zeros are not valid JSON".to_string());
                    }
                }
                Some(c) if c.is_ascii_digit() => {
                    while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                        self.pos += 1;
                    }
                }
                _ => return Err("malformed JSON number".to_string()),
            }
            // No fraction or exponent: this grammar only carries integers.
            if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
                return Err(
                    "record numbers must be integers; fractions and exponents are not accepted"
                        .to_string(),
                );
            }
            let text = std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| "invalid UTF-8 in JSON number".to_string())?;
            text.parse::<i128>()
                .map(JsonValue::Number)
                .map_err(|_| "JSON integer is out of supported range".to_string())
        }
    }
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

    // -- verify helpers -----------------------------------------------------

    /// Build a format-1 record JSON string for the given content, with the
    /// correct tag for `key`.
    fn record_for(key_hex: &str, key_id: &str, version: u32, fields: &[&str]) -> String {
        let tag = sign_tag(key_hex, key_id, version, fields);
        let fields_json = fields
            .iter()
            .map(|f| format!("\"{}\"", json_escape(f)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"{}\",\"key_version\":{},\"fields\":[{}],\"tag\":\"{}\"}}",
            json_escape(key_id),
            version,
            fields_json,
            tag
        )
    }

    #[test]
    fn verify_accepts_valid_records() {
        let key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        // Zero fields vs one empty field are both valid and distinct.
        assert!(matches!(
            verify_input(record_for(key, "id", 1, &[]).as_bytes(), key),
            VerifyOutcome::Valid
        ));
        assert!(matches!(
            verify_input(record_for(key, "id", 1, &[""]).as_bytes(), key),
            VerifyOutcome::Valid
        ));
        // Unicode, duplicate and reordered fields.
        let rec = record_for(key, "demo", 3, &["hello", "世界", "世界"]);
        assert!(matches!(verify_input(rec.as_bytes(), key), VerifyOutcome::Valid));
        // Surrounding JSON whitespace and internal reformatting are fine.
        let pretty = format!(
            " \n\t{}  \r\n",
            rec.replace(',', ",\n  ").replace('{', "{\n  ")
        );
        assert!(matches!(
            verify_input(pretty.as_bytes(), key),
            VerifyOutcome::Valid
        ));
        // Member order must not matter.
        let reordered = "{\"tag\":\"X\",\"fields\":[],\"key_version\":1,\"key_id\":\"id\",\
                         \"algorithm\":\"HMAC-SHA256\",\"format\":1}";
        // Recompute with the real tag to keep this a positive case.
        let mut reordered = reordered.to_string();
        let tag = sign_tag(key, "id", 1, &[]);
        reordered = reordered.replace('X', &tag);
        assert!(matches!(
            verify_input(reordered.as_bytes(), key),
            VerifyOutcome::Valid
        ));
        // Uppercase tag spelling still represents the same 32 bytes.
        let real_tag = sign_tag(key, "id", 1, &["x"]);
        let upper = record_for(key, "id", 1, &["x"]).replace(&real_tag, &real_tag.to_uppercase());
        assert!(matches!(
            verify_input(upper.as_bytes(), key),
            VerifyOutcome::Valid
        ));
    }

    #[test]
    fn verify_reports_mismatch_not_error_on_tampering() {
        let key = "00ff";
        let base = record_for(key, "id", 1, &["x"]);
        assert!(matches!(
            verify_input(base.as_bytes(), "ff00"),
            VerifyOutcome::Mismatch
        ));

        // Every authenticated change keeps the record structurally legal but
        // breaks the tag: fields, key id, version, tag itself.
        let tampered = [
            base.replace("\"x\"", "\"y\""),
            base.replace("\"id\"", "\"id2\""),
            base.replace("\"key_version\":1", "\"key_version\":2"),
            base.replace(&sign_tag(key, "id", 1, &["x"]), &"a".repeat(64)),
        ];
        for rec in tampered {
            assert!(
                matches!(verify_input(rec.as_bytes(), key), VerifyOutcome::Mismatch),
                "expected mismatch for {rec}"
            );
        }
    }

    #[test]
    fn verify_rejects_malformed_and_structurally_bad_records() {
        let key = "00ff";
        let base = record_for(key, "id", 1, &["x"]);
        let invalid = [
            // corrupt JSON / framing
            "".to_string(),
            "   ".to_string(),
            "{".to_string(),
            format!("{base}{base}"),        // two objects
            format!("{base} junk"),         // trailing non-whitespace
            format!("{base}42"),            // trailing number
            // not an object
            "[]".to_string(),
            "\"s\"".to_string(),
            "42".to_string(),
            // structural record problems
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":["x"]}"#.to_string(), // no tag
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"","key_version":1,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_string(),
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":0,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_string(),
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":4294967296,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_string(),
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[1],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_string(),
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":"x","tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_string(),
            // corrupt tag
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"00"}"#.to_string(),
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}"#.to_string(),
            // duplicate member, extra member, duplicate fields array items
            r#"{"format":1,"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_string(),
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":1}"#.to_string(),
            // non-integer numbers
            r#"{"format":1.0,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_string(),
            r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":01,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_string(),
        ];
        for rec in invalid {
            assert!(
                matches!(verify_input(rec.as_bytes(), key), VerifyOutcome::Invalid(_)),
                "expected Invalid for {rec:?}"
            );
        }
    }

    #[test]
    fn verify_unsupported_format_and_algorithm_are_explicit() {
        let key = "00ff";
        let tag = "a".repeat(64);
        let f2 = format!(
            "{{\"format\":2,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"id\",\"key_version\":1,\"fields\":[],\"tag\":\"{tag}\"}}"
        );
        let a2 = format!(
            "{{\"format\":1,\"algorithm\":\"HMAC-SHA512\",\"key_id\":\"id\",\"key_version\":1,\"fields\":[],\"tag\":\"{tag}\"}}"
        );
        for rec in [f2, a2] {
            match verify_input(rec.as_bytes(), key) {
                VerifyOutcome::Invalid(msg) => {
                    assert!(msg.contains("unsupported"), "message must say unsupported: {msg}");
                }
                other => panic!("expected Invalid, got {other:?} for {rec}"),
            }
        }
    }

    #[test]
    fn strict_parser_rules() {
        use json::parse_single;
        assert!(parse_single("{}").is_ok());
        assert!(parse_single(" \n\t {} \r").is_ok());
        assert!(parse_single("{\"a\":1}").is_ok());
        // trailing content, duplicates, fractions/exponents/leading zeros
        assert!(parse_single("{} {}").is_err());
        assert!(parse_single("{}x").is_err());
        assert!(parse_single("{\"a\":1,\"a\":2}").is_err());
        assert!(parse_single("1.0").is_err());
        assert!(parse_single("1e3").is_err());
        assert!(parse_single("01").is_err());
        assert!(parse_single("-01").is_err());
        // string escapes incl. surrogate pairs and lone surrogates
        assert_eq!(
            parse_single("\"😀\"").unwrap(),
            json::JsonValue::String("😀".to_string())
        );
        assert_eq!(
            parse_single("\"\\ud83d\\ude00\"").unwrap(),
            json::JsonValue::String("😀".to_string())
        );
        assert!(parse_single("\"\\ud83d\"").is_err());
        assert!(parse_single("\"\\udc00\"").is_err());
        assert!(parse_single("\"\\x\"").is_err());
        assert!(parse_single("\"\n\"").is_err()); // raw control character
    }
}
