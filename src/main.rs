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

// ---------------------------------------------------------------------------
// verify: authenticate exactly one signed record read from standard input.
// ---------------------------------------------------------------------------

struct VerifyOptions {
    key: String,
}

fn verify(args: &[String]) -> ExitCode {
    // Argument errors follow the same conventions as `sign` (exit 2, message
    // that never echoes the key or any rejected value).
    let opts = match parse_verify_args(args) {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("authnote verify: {msg}");
            return ExitCode::from(2);
        }
    };

    // JSON is a byte-oriented text format: read raw bytes and require valid
    // UTF-8 rather than silently lossy-decoding the record.
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("authnote verify: failed to read standard input: {e}");
        return ExitCode::from(2);
    }

    let outcome: Result<bool, String> = (|| {
        let record = parse_record(&input)?;
        let key_bytes = decode_hex(&opts.key).expect("key was validated as hex");
        let message = encode_message(&record.key_id, record.key_version, &record.fields);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key_bytes)
            .expect("HMAC accepts keys of any length");
        mac.update(&message);
        let expected = mac.finalize().into_bytes();
        let given = decode_hex(&record.tag).expect("tag was validated as 64 hex chars");
        // Either the whole record matches the key or it does not; the result
        // never claims which part moved or whether the key was wrong.
        Ok(constant_time_eq(&given, &expected))
    })();

    match outcome {
        Ok(valid) => {
            println!("{{\"valid\":{valid}}}");
            if valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(msg) => {
            eprintln!("authnote verify: {msg}");
            ExitCode::from(2)
        }
    }
}

/// Parse the verify command line: `--key HEX` is the only option, exactly once.
fn parse_verify_args(args: &[String]) -> Result<VerifyOptions, String> {
    let mut key: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        // Support both "--opt value" and "--opt=value" forms, like sign.
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
                if key.is_some() {
                    return Err("option --key must be given exactly once".to_string());
                }
                key = Some(v);
            }
            _ => {
                // Never echo the unrecognized argument: like sign, it may be a
                // misplaced secret.
                return Err(
                    "unrecognized option or argument (known options: --key)".to_string(),
                );
            }
        }
        i += 1;
    }

    let key = key.ok_or("missing required option --key")?;
    if key.is_empty()
        || key.len() % 2 != 0
        || !key.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("--key must be a non-empty, even-length hexadecimal string".to_string());
    }
    Ok(VerifyOptions { key })
}

/// A structurally valid format-1 record. Field order and repeats are preserved
/// exactly as decoded; reformatting or reordering object members does not
/// change the authenticated content.
struct SignedRecord {
    key_id: String,
    key_version: u32,
    fields: Vec<String>,
    tag: String,
}

/// Parse exactly one JSON record from the raw stdin bytes.
///
/// JSON whitespace is permitted before and after the single object, but
/// nothing else: an empty input, several objects or trailing non-whitespace
/// data are all rejected rather than authenticating the first object.
fn parse_record(input: &[u8]) -> Result<SignedRecord, String> {
    let text = std::str::from_utf8(input)
        .map_err(|_| "malformed JSON record: input is not valid UTF-8 text".to_string())?;
    let mut parser = JsonParser {
        chars: text.chars().collect(),
        pos: 0,
    };
    parser.skip_ws();
    if parser.pos == parser.chars.len() {
        return Err("malformed JSON record: standard input is empty".to_string());
    }
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.chars.len() {
        return Err(
            "malformed JSON record: expected exactly one JSON value with only surrounding whitespace, found trailing non-whitespace data"
                .to_string(),
        );
    }
    validate_record(value)
}

/// Compare two equal-length byte strings without short-circuiting, so the
/// exit path does not leak how many tag bytes matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Minimal strict JSON parser (RFC 8259 grammar; no third-party dependency).
//
// Deliberately stricter than a general-purpose parser in the ways the record
// contract needs: duplicate object members are rejected, only the four JSON
// whitespace characters count as whitespace, numbers must follow the grammar
// (no leading zeros, fractions/exponents still parsed so they can be reported
// as type errors), and raw control characters or unpaired surrogates in
// strings are rejected. Parse errors never quote the input.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Json {
    Null,
    // Retained for parser completeness; records carry no boolean values.
    #[allow(dead_code)]
    Bool(bool),
    /// Verbose spelling retained so callers can distinguish integers from
    /// fractional/exponential numbers when the record requires an integer.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

struct JsonParser {
    chars: Vec<char>,
    pos: usize,
}

impl JsonParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    /// RFC 8259 whitespace: space, tab, LF, CR only.
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if matches!(c, ' ' | '\t' | '\n' | '\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some('{') => Ok(Json::Obj(self.parse_object()?)),
            Some('[') => Ok(Json::Arr(self.parse_array()?)),
            Some('"') => Ok(Json::Str(self.parse_string()?)),
            Some('t') => self.parse_literal("true", Json::Bool(true)),
            Some('f') => self.parse_literal("false", Json::Bool(false)),
            Some('n') => self.parse_literal("null", Json::Null),
            Some(c) if c == '-' || c.is_ascii_digit() => Ok(Json::Num(self.parse_number()?)),
            Some(_) => Err("malformed JSON record: unexpected token".to_string()),
            None => Err("malformed JSON record: unexpected end of input".to_string()),
        }
    }

    fn parse_literal(&mut self, want: &str, value: Json) -> Result<Json, String> {
        for expected in want.chars() {
            if self.bump() != Some(expected) {
                return Err(format!("malformed JSON record: invalid literal (expected {want})"));
            }
        }
        Ok(value)
    }

    fn parse_object(&mut self) -> Result<Vec<(String, Json)>, String> {
        self.bump(); // opening '{'
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.bump();
            return Ok(entries);
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err("malformed JSON record: expected a string member name".to_string());
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(k, _)| k == &key) {
                return Err(
                    "malformed JSON record: object contains a duplicate member".to_string(),
                );
            }
            self.skip_ws();
            if self.bump() != Some(':') {
                return Err("malformed JSON record: expected ':' after member name".to_string());
            }
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err("malformed JSON record: expected ',' or '}' in object".to_string()),
            }
        }
        Ok(entries)
    }

    fn parse_array(&mut self) -> Result<Vec<Json>, String> {
        self.bump(); // opening '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.bump();
            return Ok(items);
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.bump() {
                Some(',') => {
                    self.skip_ws();
                    continue;
                }
                Some(']') => break,
                _ => return Err("malformed JSON record: expected ',' or ']' in array".to_string()),
            }
        }
        Ok(items)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.bump(); // opening quote
        let mut out = String::new();
        loop {
            let c = self
                .bump()
                .ok_or_else(|| "malformed JSON record: unterminated string".to_string())?;
            match c {
                '"' => break,
                '\\' => {
                    let e = self
                        .bump()
                        .ok_or_else(|| "malformed JSON record: unterminated escape".to_string())?;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hi = self.parse_hex4()?;
                            let scalar = if (0xD800..=0xDBFF).contains(&hi) {
                                if self.bump() != Some('\\') || self.bump() != Some('u') {
                                    return Err(
                                        "malformed JSON record: unpaired UTF-16 high surrogate"
                                            .to_string(),
                                    );
                                }
                                let lo = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err(
                                        "malformed JSON record: invalid UTF-16 surrogate pair"
                                            .to_string(),
                                    );
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..=0xDFFF).contains(&hi) {
                                return Err(
                                    "malformed JSON record: unpaired UTF-16 low surrogate"
                                        .to_string(),
                                );
                            } else {
                                hi
                            };
                            out.push(
                                char::from_u32(scalar)
                                    .expect("surrogate arithmetic yields a valid scalar"),
                            );
                        }
                        _ => {
                            return Err(
                                "malformed JSON record: invalid escape sequence in string"
                                    .to_string(),
                            )
                        }
                    }
                }
                c if (c as u32) < 0x20 => {
                    return Err(
                        "malformed JSON record: unescaped control character in string".to_string(),
                    )
                }
                c => out.push(c),
            }
        }
        Ok(out)
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let c = self
                .bump()
                .ok_or_else(|| "malformed JSON record: truncated \\u escape".to_string())?;
            let digit = c
                .to_digit(16)
                .ok_or_else(|| "malformed JSON record: invalid hexadecimal digit in \\u escape".to_string())?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<String, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.bump();
        }
        match self.peek() {
            Some('0') => {
                self.bump();
            }
            Some(c) if c.is_ascii_digit() => {
                self.bump();
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.bump();
                }
            }
            _ => return Err("malformed JSON record: invalid number".to_string()),
        }
        if self.peek() == Some('.') {
            self.bump();
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return Err("malformed JSON record: fraction requires digits".to_string());
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            self.bump();
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.bump();
            }
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return Err("malformed JSON record: exponent requires digits".to_string());
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
            }
        }
        Ok(self.chars[start..self.pos].iter().collect())
    }
}

/// How a grammar-valid JSON number token behaves as the unsigned integer the
/// record schema requires.
enum UintToken {
    Exactly(u64),
    /// Grammar-valid decimal integer that does not fit in `u64`.
    TooLarge,
    /// Negative, fractional or exponential spelling.
    NotAnInteger,
}

fn classify_uint(token: &str) -> UintToken {
    if !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit()) {
        match token.parse::<u64>() {
            Ok(v) => UintToken::Exactly(v),
            Err(_) => UintToken::TooLarge,
        }
    } else {
        UintToken::NotAnInteger
    }
}

/// Validate the parsed JSON value against the documented record schema and
/// convert it into a [`SignedRecord`]. Messages name structural problems only;
/// they never quote values from the input record.
fn validate_record(value: Json) -> Result<SignedRecord, String> {
    let entries = match value {
        Json::Obj(entries) => entries,
        _ => {
            return Err(
                "malformed record: top-level value must be a single JSON object".to_string(),
            )
        }
    };

    let mut format: Option<Json> = None;
    let mut algorithm: Option<Json> = None;
    let mut key_id: Option<Json> = None;
    let mut key_version: Option<Json> = None;
    let mut fields: Option<Json> = None;
    let mut tag: Option<Json> = None;

    for (name, value) in entries {
        let slot: &mut Option<Json> = match name.as_str() {
            "format" => &mut format,
            "algorithm" => &mut algorithm,
            "key_id" => &mut key_id,
            "key_version" => &mut key_version,
            "fields" => &mut fields,
            "tag" => &mut tag,
            // Reject unknown members rather than authenticating a record whose
            // structure is not the documented one. The unexpected name is not
            // echoed back.
            _ => {
                return Err(
                    "malformed record: unexpected member; only format, algorithm, key_id, key_version, fields and tag are allowed"
                        .to_string(),
                )
            }
        };
        // Duplicate names were already refused by the parser.
        *slot = Some(value);
    }

    // format: integer 1. Any other integer is an explicitly *unsupported*
    // version, not a malformed record, and must never fall through to the
    // format-1 computation.
    match format {
        Some(Json::Num(token)) => match classify_uint(&token) {
            UintToken::Exactly(v) if v == u64::from(FORMAT_VERSION) => {}
            UintToken::Exactly(_) | UintToken::TooLarge => {
                return Err(
                    "unsupported format version; only format version 1 is supported".to_string(),
                )
            }
            UintToken::NotAnInteger => {
                return Err("malformed record: format must be a non-negative integer".to_string())
            }
        },
        Some(_) => return Err("malformed record: format must be a non-negative integer".to_string()),
        None => return Err("malformed record: missing required member format".to_string()),
    }

    // algorithm: exact fixed name; anything else is explicitly unsupported.
    match algorithm {
        Some(Json::Str(name)) if name == ALGORITHM => {}
        Some(Json::Str(_)) => {
            return Err(format!(
                "unsupported algorithm; only {ALGORITHM} is supported"
            ))
        }
        Some(_) => return Err("malformed record: algorithm must be a JSON string".to_string()),
        None => return Err("malformed record: missing required member algorithm".to_string()),
    }

    // key_id: non-empty string.
    let key_id = match key_id {
        Some(Json::Str(s)) => s,
        Some(_) => return Err("malformed record: key_id must be a JSON string".to_string()),
        None => return Err("malformed record: missing required member key_id".to_string()),
    };
    if key_id.is_empty() {
        return Err("malformed record: key_id must not be empty".to_string());
    }

    // key_version: integer in the same range sign accepts.
    let key_version = match key_version {
        Some(Json::Num(token)) => match classify_uint(&token) {
            UintToken::Exactly(v) if (1..=u64::from(u32::MAX)).contains(&v) => v as u32,
            _ => {
                return Err(
                    "malformed record: key_version must be an integer between 1 and 4294967295"
                        .to_string(),
                )
            }
        },
        Some(_) => {
            return Err(
                "malformed record: key_version must be an integer between 1 and 4294967295"
                    .to_string(),
            )
        }
        None => return Err("malformed record: missing required member key_version".to_string()),
    };

    // fields: array of strings only. Order and repeats are message content.
    let fields = match fields {
        Some(Json::Arr(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Json::Str(s) => out.push(s),
                    _ => {
                        return Err(
                            "malformed record: every field must be a JSON string".to_string(),
                        )
                    }
                }
            }
            out
        }
        Some(_) => return Err("malformed record: fields must be a JSON array".to_string()),
        None => return Err("malformed record: missing required member fields".to_string()),
    };

    // tag: exactly 32 bytes as hexadecimal; either letter case is accepted,
    // matching how --key itself is decoded.
    let tag = match tag {
        Some(Json::Str(s)) => s,
        Some(_) => return Err("malformed record: tag must be a JSON string".to_string()),
        None => return Err("malformed record: missing required member tag".to_string()),
    };
    if tag.len() != 64 || !tag.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(
            "malformed record: tag must encode exactly 32 bytes as 64 hexadecimal characters"
                .to_string(),
        );
    }

    Ok(SignedRecord {
        key_id,
        key_version,
        fields,
        tag,
    })
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
