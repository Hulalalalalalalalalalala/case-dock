use std::env;
use std::io::Read;
use std::process::ExitCode;

/// Authentication core shared by `sign` and `verify`.
///
/// This module owns everything about *computing* format-1 tags: key
/// validation and decoding, the key-version business rule (its legal range
/// and the canonical integer both entry points authenticate with), the
/// canonical byte encoding of the authenticated content, the HMAC-SHA256
/// computation itself, and constant-time tag comparison. It knows nothing
/// about command lines, JSON records, standard output or exit codes — the
/// subcommands own all of that presentation (including each one's input
/// grammar and error wording) and map these results to output lines and exit
/// statuses.
mod auth {
    use hmac::{
        Hmac, Mac,
        digest::KeyInit,
    };
    use sha2::Sha256;

    /// Record format version written by `sign` and required by `verify`.
    pub const FORMAT_VERSION: u32 = 1;
    /// Algorithm name written by `sign` and required by `verify`.
    pub const ALGORITHM: &str = "HMAC-SHA256";
    /// Smallest legal key version; the low endpoint is itself a usable version.
    pub const MIN_KEY_VERSION: u32 = 1;
    /// Largest legal key version. The version travels in the record and in the
    /// format-1 encoding as a `u32`, so the bound is exactly `u32::MAX`.
    pub const MAX_KEY_VERSION: u32 = u32::MAX;
    /// Domain separator that also records the format version, so tags computed
    /// by different versions of the encoding can never collide.
    const DOMAIN_SEPARATOR: &[u8] = b"authnote-sign-v1";

    /// One computed authentication tag: a full HMAC-SHA256 output.
    pub type Tag = [u8; 32];

    /// Shared key validation for `sign` and `verify`: non-empty even-length
    /// hex. The rejected value is never included in the message.
    pub fn validate_key_hex(key: &str) -> Result<(), String> {
        if key.is_empty() || key.len() % 2 != 0 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("--key must be a non-empty, even-length hexadecimal string".to_string());
        }
        Ok(())
    }

    /// Decode key text that has passed `validate_key_hex` into raw bytes.
    /// The bytes feed the MAC only; they never appear in any record.
    pub fn decode_key(hex: &str) -> Vec<u8> {
        decode_hex(hex).expect("key was validated as hex")
    }

    /// Apply the key-version business rule to an exact integer value and
    /// return its canonical `u32` form.
    ///
    /// Both entry points funnel through this one function, so the legal range
    /// (`MIN_KEY_VERSION..=MAX_KEY_VERSION`) and the integer that actually
    /// enters the record and the format-1 encoding live in exactly one place:
    /// `sign` hands over the value parsed from its decimal command-line text,
    /// `verify` the value read from a strict JSON integer. What differs is
    /// only each side's input grammar (leading zeros and signs are accepted
    /// by neither JSON nor the CLI in the same way) — that parsing stays with
    /// the caller; the rule itself does not.
    pub fn canonical_key_version(value: i128) -> Option<u32> {
        (i128::from(MIN_KEY_VERSION)..=i128::from(MAX_KEY_VERSION))
            .contains(&value)
            .then(|| value as u32)
    }

    /// Fixed range-rejection wording for a record's `key_version`. The message
    /// names the member and the bounds, never the rejected value.
    pub fn key_version_range_error() -> String {
        format!(
            "member \"key_version\" is outside the supported range {}..={}",
            MIN_KEY_VERSION, MAX_KEY_VERSION
        )
    }

    /// Fixed range-rejection wording for sign's `--key-version` option. The
    /// message names the option and the bounds, never the rejected text.
    pub fn key_version_option_error() -> String {
        format!(
            "--key-version must be a decimal integer between {} and {}",
            MIN_KEY_VERSION, MAX_KEY_VERSION
        )
    }

    /// Compute the format-1 authentication tag over the given content.
    ///
    /// Both `sign` (to emit a tag) and `verify` (to recompute the expected
    /// tag) go through this single path, so the two can never drift apart.
    pub fn compute_tag(key: &[u8], key_id: &str, key_version: u32, fields: &[String]) -> Tag {
        let message = encode_message(key_id, key_version, fields);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
            .expect("HMAC accepts keys of any length");
        mac.update(&message);
        mac.finalize().into_bytes().into()
    }

    /// Compare a recomputed tag with the tag from a record, in constant time
    /// so a mismatch cannot be recovered one byte at a time through timing.
    pub fn tags_match(expected: &Tag, given: &[u8]) -> bool {
        if expected.len() != given.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(given.iter()) {
            diff |= a ^ b;
        }
        diff == 0
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

    pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }

    pub fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

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

/// Shared command-line option grammar for `sign` and `verify`.
///
/// Both subcommands accept the same two spellings for every option:
///   --name value     (the following argument is the value, even when it
///                    itself starts with "--")
///   --name=value     (everything after the first '=' is the value; further
///                    '=' characters stay part of the value)
/// and the two forms may be mixed freely.
///
/// What differs between the subcommands is only *which* option names are
/// allowed and whether a name may repeat, so each caller supplies its own
/// option table. Values that fail are never quoted back in error messages:
/// the messages name known options only, never the rejected text (which may
/// be a mistyped secret).
mod options {
    /// How many times an option name may appear on one command line.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Multiplicity {
        /// At most once; a second occurrence is a usage error.
        Single,
        /// Any number of times; values are kept in order of appearance.
        Repeated,
    }

    /// One option accepted by a subcommand.
    pub(super) struct Spec {
        pub(super) name: &'static str,
        pub(super) multiplicity: Multiplicity,
    }

    /// A matched option occurrence: the option's index in the table and its
    /// value for this occurrence.
    pub(super) struct Occurrence {
        pub(super) spec_index: usize,
        pub(super) value: String,
    }

    /// Parse `args` against `specs`, preserving order of appearance.
    ///
    /// Error precedence (first problem wins, left to right):
    /// missing value for an option, repeated single-use option, unknown
    /// option or bare argument. Callers run their own semantic validation
    /// (hex, ranges, ...) afterwards, so grammar problems are always
    /// reported before invalid values.
    pub(super) fn parse(args: &[String], specs: &[Spec]) -> Result<Vec<Occurrence>, String> {
        let mut out = Vec::new();
        let mut seen_once = vec![false; specs.len()];

        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            // Support both "--opt value" and "--opt=value" forms. With '='
            // the value is everything after the FIRST '='; '=' characters
            // inside the value are left untouched.
            let (name, inline_value) = match arg.split_once('=') {
                Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
                _ => (arg.as_str(), None),
            };
            let spec_index = match specs.iter().position(|s| s.name == name) {
                Some(idx) => idx,
                // Never echo the unrecognized argument itself: it may be a
                // misplaced secret (e.g. a key value whose option name was
                // mistyped or whose value was consumed by another option).
                None => return Err(unknown_option_error(specs)),
            };
            let value = match inline_value {
                Some(v) => v,
                None => {
                    // The immediately following argument is the value, with
                    // no "--"-prefix special-casing: a field or key id may
                    // legitimately start with two dashes.
                    i += 1;
                    match args.get(i) {
                        Some(v) => v.clone(),
                        None => return Err(format!("option {name} requires a value")),
                    }
                }
            };
            if specs[spec_index].multiplicity == Multiplicity::Single && seen_once[spec_index] {
                return Err(format!("option {name} must be given exactly once"));
            }
            seen_once[spec_index] = true;
            out.push(Occurrence { spec_index, value });
            i += 1;
        }
        Ok(out)
    }

    /// Build the fixed "unrecognized" message for a subcommand, listing only
    /// that subcommand's known option names. The rejected argument is never
    /// included.
    fn unknown_option_error(specs: &[Spec]) -> String {
        let names = specs
            .iter()
            .map(|s| s.name)
            .collect::<Vec<_>>()
            .join(", ");
        if specs.len() == 1 {
            format!("unrecognized option or argument (the only known option is {names})")
        } else {
            format!("unrecognized option or argument (known options: {names})")
        }
    }
}

fn sign(args: &[String]) -> ExitCode {
    match parse_sign_args(args).and_then(validate_sign_args) {
        Ok(opts) => {
            let key_bytes = auth::decode_key(&opts.key);
            // `opts.key_version` is already the canonical integer produced by
            // the shared key-version rule, so there is no second conversion
            // here: the same value goes into the record and the tag.
            let tag = auth::compute_tag(&key_bytes, &opts.key_id, opts.key_version, &opts.fields);
            println!("{}", render_record(&opts.key_id, opts.key_version, &opts.fields, &tag));
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("authnote sign: {msg}");
            ExitCode::from(2)
        }
    }
}

/// Render one format-1 record as the single JSON line `sign` prints.
///
/// Pure presentation: member order, escaping, lowercase tag hex and the
/// trailing newline (added by the caller's `println!`) are fixed here. The
/// key is not a parameter — it never enters the record.
fn render_record(key_id: &str, key_version: u32, fields: &[String], tag: &auth::Tag) -> String {
    let fields_json = fields
        .iter()
        .map(|f| format!("\"{}\"", json_escape(f)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"format\":{},\"algorithm\":\"{}\",\"key_id\":\"{}\",\"key_version\":{},\"fields\":[{}],\"tag\":\"{}\"}}",
        auth::FORMAT_VERSION,
        auth::ALGORITHM,
        json_escape(key_id),
        key_version,
        fields_json,
        auth::hex_encode(tag),
    )
}

/// Validated sign inputs. `key_version` is already the canonical integer
/// produced by the shared key-version rule, so `sign` converts nothing again.
struct SignOptions {
    key: String,
    key_id: String,
    key_version: u32,
    fields: Vec<String>,
}

/// sign's option table: the three credential/metadata options are single
/// use; only --field may repeat. Names double as their stable indices.
const SIGN_OPTIONS: &[options::Spec] = &[
    options::Spec {
        name: "--key",
        multiplicity: options::Multiplicity::Single,
    },
    options::Spec {
        name: "--key-id",
        multiplicity: options::Multiplicity::Single,
    },
    options::Spec {
        name: "--key-version",
        multiplicity: options::Multiplicity::Single,
    },
    options::Spec {
        name: "--field",
        multiplicity: options::Multiplicity::Repeated,
    },
];
const SIGN_KEY_INDEX: usize = 0;
const SIGN_KEY_ID_INDEX: usize = 1;
const SIGN_KEY_VERSION_INDEX: usize = 2;

/// Raw sign options straight off the command line: values are unvalidated
/// text, so the option grammar (in `options::parse`) stays separate from the
/// value rules applied in `validate_sign_args`.
struct RawSignOptions {
    key: String,
    key_id: String,
    key_version: String,
    fields: Vec<String>,
}

fn parse_sign_args(args: &[String]) -> Result<RawSignOptions, String> {
    let mut key: Option<String> = None;
    let mut key_id: Option<String> = None;
    let mut key_version: Option<String> = None;
    let mut fields: Vec<String> = Vec::new();

    for occurrence in options::parse(args, SIGN_OPTIONS)? {
        match occurrence.spec_index {
            SIGN_KEY_INDEX => key = Some(occurrence.value),
            SIGN_KEY_ID_INDEX => key_id = Some(occurrence.value),
            SIGN_KEY_VERSION_INDEX => key_version = Some(occurrence.value),
            // Field values are appended in order of appearance; repeats,
            // empty strings and text starting with "--" are kept verbatim.
            _ => fields.push(occurrence.value),
        }
    }

    let key = key.ok_or("missing required option --key")?;
    let key_id = key_id.ok_or("missing required option --key-id")?;
    let key_version = key_version.ok_or("missing required option --key-version")?;
    Ok(RawSignOptions {
        key,
        key_id,
        key_version,
        fields,
    })
}

/// sign's own key-version input grammar: non-empty ASCII decimal text, then
/// the shared range rule. Leading zeros are command-line text, not JSON, so
/// "007" is the integer 7; signs, fractions, exponents and embedded
/// whitespace are not part of the grammar. The rejected text is never quoted.
fn parse_key_version_text(text: &str) -> Result<u32, String> {
    let value = (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse::<i128>().ok())
        .flatten();
    match value.and_then(auth::canonical_key_version) {
        Some(version) => Ok(version),
        None => Err(auth::key_version_option_error()),
    }
}

fn validate_sign_args(opts: RawSignOptions) -> Result<SignOptions, String> {
    // Never echo the key back in error messages.
    auth::validate_key_hex(&opts.key)?;
    if opts.key_id.is_empty() {
        return Err("--key-id must not be empty".to_string());
    }
    let key_version = parse_key_version_text(&opts.key_version)?;
    Ok(SignOptions {
        key: opts.key,
        key_id: opts.key_id,
        key_version,
        fields: opts.fields,
    })
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn verify(args: &[String]) -> ExitCode {
    // verify deliberately shares sign's option grammar through the common
    // parser but declares its own, narrower table: --key is the only known
    // option, so every sign-only option (--key-id, --key-version, --field)
    // is rejected here as unrecognized. Values that fail are never echoed
    // (they could be a mistyped secret).
    const VERIFY_OPTIONS: &[options::Spec] = &[options::Spec {
        name: "--key",
        multiplicity: options::Multiplicity::Single,
    }];

    let parse = (|| -> Result<String, String> {
        let occurrences = options::parse(args, VERIFY_OPTIONS)?;
        // The parser enforces "at most one --key"; take it if present.
        let key = occurrences
            .first()
            .map(|o| o.value.clone())
            .ok_or("missing required option --key")?;
        auth::validate_key_hex(&key)?;
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

    let key_bytes = auth::decode_key(key_hex);
    let expected_tag = auth::compute_tag(
        &key_bytes,
        &record.key_id,
        record.key_version,
        &record.fields,
    );

    if auth::tags_match(&expected_tag, &record.tag) {
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
    auth::decode_hex(s).map_err(|e| format!("tag is not valid hexadecimal: {e}"))
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

    // Unsupported format versions must be reported as such explicitly: we do
    // not silently fall back to the current rules and compute a result. The
    // decision is purely "is the integer spelling 1 or not", so zero, negative
    // and integers wider than the machine's usual integer capacity all say
    // "unsupported version" rather than "corrupt input"; non-integer spellings
    // (strings, fractions, exponents, leading zeros) stay type/grammar errors.
    let format = format.ok_or("record is missing required member \"format\"")?;
    match format {
        json::JsonValue::Number(n) if n.is_one() => {}
        json::JsonValue::Number(_) => {
            return Err("unsupported record format version; only format 1 is supported".to_string())
        }
        _ => return Err("member \"format\" must be an integer".to_string()),
    }

    let algorithm = algorithm.ok_or("record is missing required member \"algorithm\"")?;
    match algorithm {
        json::JsonValue::String(s) if s == auth::ALGORITHM => {}
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
            // Type/writing problems are caught by the strict parser and the
            // non-Number arm below; here the only question the shared
            // key-version rule answers is whether the exact integer is in
            // range. An integer wider than `i128` yields `None` from
            // `as_i128` and is rejected by the same rule as a small
            // out-of-range value — it must never be truncated or wrapped, and
            // never misreported as an unsupported record format.
            match n.as_i128().and_then(auth::canonical_key_version) {
                Some(version) => version,
                None => return Err(auth::key_version_range_error()),
            }
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
    /// An integer written with a legal JSON decimal spelling (optional sign,
    /// no leading zero, no fraction or exponent). The spelling is kept rather
    /// than the numeric value so integers wider than `i128` stay representable:
    /// a version field merely has to tell "1" apart from any other integer,
    /// which is a lexical decision and must never truncate or reject the value
    /// just because it is too large for the machine's widest integer.
    #[derive(Debug, PartialEq, Eq)]
    pub enum JsonInt {
        /// Integer that fits in `i128`; carries its exact value.
        Small(i128),
        /// Legal integer spelling that is outside the `i128` range, kept as
        /// its exact decimal text (including a leading '-'). Never truncated,
        /// rounded or treated as 1.
        Large(String),
    }

    impl JsonInt {
        /// Parse a strictly-written JSON integer spelling (the caller has
        /// already enforced the grammar, including no leading zeros) without
        /// rejecting values wider than `i128`.
        fn from_strict_spelling(text: &str) -> JsonInt {
            match text.parse::<i128>() {
                Ok(n) => JsonInt::Small(n),
                // parse only fails here because the magnitude is out of range;
                // the spelling itself is valid JSON, so retain it verbatim.
                Err(_) => JsonInt::Large(text.to_string()),
            }
        }

        /// Whether the integer is exactly the value 1: true only for the
        /// canonical spelling "1" (a `Large` value can never equal 1).
        pub fn is_one(&self) -> bool {
            matches!(self, JsonInt::Small(1))
        }

        /// Exact value when it fits in `i128`; out-of-range spellings yield
        /// `None` instead of being truncated or wrapped.
        pub fn as_i128(&self) -> Option<i128> {
            match self {
                JsonInt::Small(n) => Some(*n),
                JsonInt::Large(_) => None,
            }
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum JsonValue {
        /// Parsed as an integer because the record grammar has no fractional
        /// values. Integers beyond `i128` stay legal JSON and are retained as
        /// their exact spelling (see `JsonInt::Large`).
        Number(JsonInt),
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
        /// values, so `.`/`e` forms are rejected rather than truncated. A
        /// syntactically legal integer is never rejected for being wider than
        /// `i128`: it is retained verbatim so callers can classify it (for
        /// example, an unsupported format version) without truncating the
        /// value or confusing it with corrupt JSON.
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
            Ok(JsonValue::Number(JsonInt::from_strict_spelling(text)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_tag(key_hex: &str, key_id: &str, version: u32, fields: &[&str]) -> String {
        let key = auth::decode_key(key_hex);
        let owned: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
        auth::hex_encode(&auth::compute_tag(&key, key_id, version, &owned))
    }

    #[test]
    // RFC 4231 test case 1: HMAC-SHA256 with key 0x0b*20, data "Hi There".
    fn hmac_matches_rfc4231() {
        use hmac::{Hmac, Mac, digest::KeyInit};
        use sha2::Sha256;
        let key = auth::decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(b"Hi There");
        assert_eq!(
            auth::hex_encode(&mac.finalize().into_bytes()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    // RFC 4231 test case 6: HMAC-SHA256 with a 131-byte key (longer than the
    // 64-byte SHA-256 block, so the key itself is hashed first), data
    // "Test Using Larger Than Block-Size Key - Hash Key First".
    fn hmac_long_key_matches_rfc4231() {
        use hmac::{Hmac, Mac, digest::KeyInit};
        use sha2::Sha256;
        let key = vec![0xaau8; 131];
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            auth::hex_encode(&mac.finalize().into_bytes()),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
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
    fn verify_key_version_boundaries_tamper_and_illegal_spellings() {
        let key = "00ff";
        let wrong_key = "0102";

        // Both range endpoints are ordinary versions: a key version other
        // than 1 is distinct from the (also 1) record format version and must
        // never surface as an unsupported format.
        for version in [1u32, 4294967295] {
            let rec = record_for(key, "id", version, &["x"]);
            assert!(
                matches!(verify_input(rec.as_bytes(), key), VerifyOutcome::Valid),
                "version {version} must verify with the correct key"
            );
            assert!(
                matches!(verify_input(rec.as_bytes(), wrong_key), VerifyOutcome::Mismatch),
                "version {version} under a wrong key is a mismatch"
            );
        }

        // Another in-range integer with the original tag is a legal record but
        // different authenticated content: mismatch under either key, never a
        // structural error.
        let v1 = record_for(key, "id", 1, &["x"]);
        let vmax_tag = sign_tag(key, "id", 4294967295, &["x"]);
        let tampered = [
            v1.replace("\"key_version\":1", "\"key_version\":2"),
            v1.replace("\"key_version\":1", "\"key_version\":4294967295"),
            record_for(key, "id", 4294967295, &["x"])
                .replace(&vmax_tag, &sign_tag(key, "id", 1, &["x"])),
        ];
        for rec in tampered {
            for k in [key, wrong_key] {
                assert!(
                    matches!(verify_input(rec.as_bytes(), k), VerifyOutcome::Mismatch),
                    "expected mismatch for {rec}"
                );
            }
        }

        // Illegal spellings/ranges are corrupt input regardless of the key;
        // none is accepted as integer 7 or wrapped/truncated into range.
        let zeros = "a".repeat(64);
        let raw_record = |token: &str| {
            format!(
                "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"id\",\
                 \"key_version\":{token},\"fields\":[\"x\"],\"tag\":\"{zeros}\"}}"
            )
        };
        let illegal = [
            "\"7\"",
            "7.0",
            "7e0",
            "007",
            "0",
            "-0",
            "-1",
            "4294967296",
            "99999999999999999999999999999999999999999",
        ];
        for token in illegal {
            for k in [key, wrong_key] {
                match verify_input(raw_record(token).as_bytes(), k) {
                    VerifyOutcome::Invalid(msg) => {
                        let lower = msg.to_lowercase();
                        assert!(
                            lower.contains("number")
                                || lower.contains("integer")
                                || lower.contains("version"),
                            "token {token}: message must describe the number/version problem: {msg}"
                        );
                    }
                    other => panic!("token {token}: expected Invalid, got {other:?}"),
                }
            }
        }

        // Legal JSON whitespace around members leaves the version's meaning
        // intact (a tampered in-range version is still just a mismatch).
        let spaced = v1.replace("\"key_version\":1", "\"key_version\" : 2 ");
        assert!(matches!(
            verify_input(spaced.as_bytes(), key),
            VerifyOutcome::Mismatch
        ));
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
    fn verify_any_legal_integer_format_other_than_1_is_unsupported_version() {
        // Every spelling below is a legal JSON decimal integer and all other
        // members satisfy the record grammar. The conclusion must be the same
        // "unsupported format version" (never corrupt input, never a
        // mismatch), regardless of the key supplied, and the oversized digits
        // must neither be truncated nor collapse to 1.
        let tag = "a".repeat(64);
        let record = |fmt: &str| {
            format!(
                "{{\"format\":{fmt},\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"id\",\"key_version\":1,\"fields\":[],\"tag\":\"{tag}\"}}"
            )
        };
        let unsupported = [
            "0",
            "-0",
            "-1",
            "2",
            "4294967296",
            // 2^127: one past i128::MAX, the reported field case.
            "170141183460469231731687303715884105728",
            // A far larger positive integer...
            "999999999999999999999999999999999999999999999999999",
            // ...and a far larger-magnitude negative one.
            "-170141183460469231731687303715884105729",
            "-999999999999999999999999999999999999999999999999999",
        ];
        for token in unsupported {
            for key in ["00ff", "0102"] {
                match verify_input(record(token).as_bytes(), key) {
                    VerifyOutcome::Invalid(msg) => {
                        let lower = msg.to_lowercase();
                        assert!(
                            lower.contains("unsupported"),
                            "token {token}: must report an unsupported version: {msg}"
                        );
                        assert!(
                            lower.contains("format"),
                            "token {token}: message must name the format version: {msg}"
                        );
                        assert!(
                            msg.contains("format 1"),
                            "token {token}: message must say only format 1 is supported: {msg}"
                        );
                        // The rejected digits must not be quoted back.
                        assert!(
                            !msg.contains(token),
                            "token {token}: message must not echo the rejected number: {msg}"
                        );
                    }
                    other => panic!("token {token}: expected Invalid, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn verify_bad_format_spellings_keep_their_own_reason_not_version_unsupported() {
        let tag = "a".repeat(64);
        // (raw format value, text the stderr must contain) — each is a distinct
        // corruption reason and none must be laundered into "unsupported
        // version", nor accepted as version 1.
        let cases: &[(&str, &str)] = &[
            ("\"1\"", "must be an integer"),
            ("1.0", "integers"),
            ("1e0", "integers"),
            ("01", "leading zeros"),
            ("-01", "leading zeros"),
            ("true", "must be an integer"),
        ];
        for (token, expected) in cases {
            let rec = format!(
                "{{\"format\":{token},\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"id\",\"key_version\":1,\"fields\":[],\"tag\":\"{tag}\"}}"
            );
            match verify_input(rec.as_bytes(), "00ff") {
                VerifyOutcome::Invalid(msg) => {
                    assert!(
                        !msg.to_lowercase().contains("unsupported"),
                        "token {token}: bad spelling is corrupt input, not an unsupported version: {msg}"
                    );
                    assert!(
                        msg.to_lowercase().contains(expected),
                        "token {token}: expected message about {expected:?}: {msg}"
                    );
                }
                other => panic!("token {token}: expected Invalid, got {other:?}"),
            }
        }

        // Missing format keeps the missing-member reason even though every
        // other member (including a large key-version spelling) is present.
        let missing = format!(
            "{{\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"id\",\"key_version\":1,\"fields\":[],\"tag\":\"{tag}\"}}"
        );
        match verify_input(missing.as_bytes(), "00ff") {
            VerifyOutcome::Invalid(msg) => {
                assert!(msg.contains("missing required member \"format\""), "got: {msg}");
                assert!(!msg.to_lowercase().contains("unsupported"), "got: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_framing_errors_take_precedence_over_format_version() {
        // A present (even unsupported) format must not produce a version
        // conclusion when the document itself is not one complete record.
        let rec = "{\"format\":2,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"id\",\
                   \"key_version\":1,\"fields\":[],\"tag\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}";
        let framed = [
            format!("{rec} junk"),
            format!("{rec}{rec}"),
            "{".to_string(),
            // duplicate member anywhere is rejected by the strict parser
            format!(
                "{{\"format\":2,\"format\":2,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"id\",\
                 \"key_version\":1,\"fields\":[],\"tag\":\"{}\"}}",
                "a".repeat(64)
            ),
        ];
        for input in framed {
            match verify_input(input.as_bytes(), "00ff") {
                VerifyOutcome::Invalid(msg) => {
                    assert!(
                        !msg.to_lowercase().contains("unsupported"),
                        "framing error must not become a version conclusion: {msg}"
                    );
                }
                other => panic!("expected Invalid for {input:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn verify_oversized_key_version_is_an_illegal_version_not_bad_format() {
        // Legal integer spellings far beyond u32 (and i128) stay *key version*
        // range errors; this fix must not widen the key-version range nor
        // reclassify them as an unsupported record format.
        let tag = "a".repeat(64);
        for token in [
            "4294967296",
            "170141183460469231731687303715884105728",
            "999999999999999999999999999999999999999999999999999",
            "-170141183460469231731687303715884105729",
        ] {
            let rec = format!(
                "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"id\",\"key_version\":{token},\"fields\":[],\"tag\":\"{tag}\"}}"
            );
            for key in ["00ff", "0102"] {
                match verify_input(rec.as_bytes(), key) {
                    VerifyOutcome::Invalid(msg) => {
                        assert!(
                            msg.contains("key_version"),
                            "token {token}: must blame key_version range: {msg}"
                        );
                        assert!(
                            !msg.to_lowercase().contains("unsupported"),
                            "token {token}: oversized key_version is not an unsupported record format: {msg}"
                        );
                        assert!(!msg.contains(token), "token {token}: must not echo the number: {msg}");
                    }
                    other => panic!("token {token}: expected Invalid, got {other:?}"),
                }
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

    #[test]
    fn json_nesting_is_capped_at_64_containers_along_one_path() {
        use json::parse_single;
        // n nested arrays around an (empty) innermost array.
        let arrays = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        // n nested objects around an integer leaf.
        let objects = |n: usize| format!("{}1{}", "{\"x\":".repeat(n), "}".repeat(n));
        // n alternating arrays/objects around an integer leaf.
        let mixed = |n: usize| {
            let mut s = String::new();
            for i in 0..n {
                s.push_str(if i % 2 == 0 { "[" } else { "{\"x\":" });
            }
            s.push('1');
            for i in (0..n).rev() {
                s.push_str(if i % 2 == 0 { "]" } else { "}" });
            }
            s
        };

        // Exactly 64 containers along one path parse; the 65th is rejected,
        // for arrays, objects and the two alternating alike.
        let builds: [fn(usize) -> String; 3] = [arrays, objects, mixed];
        for build in builds {
            assert!(parse_single(&build(64)).is_ok());
            let err = parse_single(&build(65)).unwrap_err();
            assert!(
                err.contains("nesting") && err.contains("deep"),
                "error must say the nesting is too deep: {err}"
            );
        }

        // Sibling containers at one level never add up.
        let siblings = format!("[{}]", vec!["[]"; 200].join(","));
        assert!(parse_single(&siblings).is_ok());

        // Brackets and braces inside strings are text, not containers.
        assert!(parse_single("\"[[[[[[{{{{{{]]]]]]\"").is_ok());
    }

    #[test]
    fn member_names_compare_by_decoded_text() {
        use json::parse_single;
        // A \u escape spelling of a member name is the same name once
        // decoded, so it collides with the direct spelling (and with another
        // escape spelling) no matter which comes first or whether the values
        // agree.
        assert!(parse_single("{\"a\":1,\"\\u0061\":2}").is_err());
        assert!(parse_single("{\"\\u0061\":1,\"a\":2}").is_err());
        assert!(parse_single("{\"a\":1,\"\\u0061\":1}").is_err());
        assert!(parse_single("{\"\\u0061\":1,\"\\u0061\":2}").is_err());
        // Distinct decoded names stay distinct, escape spelling or not.
        assert!(parse_single("{\"a\":1,\"\\u0062\":2}").is_ok());
    }

    #[test]
    fn verify_algorithm_name_is_matched_on_the_decoded_string() {
        let key = "00ff";
        let wrong_key = "0102";
        let tag = sign_tag(key, "id", 1, &["x"]);
        let record = |algorithm_json: &str| {
            format!(
                "{{\"format\":1,\"algorithm\":{algorithm_json},\"key_id\":\"id\",\"key_version\":1,\"fields\":[\"x\"],\"tag\":\"{tag}\"}}"
            )
        };

        // Direct and unicode-escape spellings of the one supported name are
        // the same decoded string and verify identically; under a wrong key
        // each stays a plain mismatch.
        for spelling in [
            "\"HMAC-SHA256\"",
            "\"\\u0048MAC-SHA256\"",
            "\"HMAC\\u002dSHA256\"",
            "\"HMAC-SHA\\u003256\"",
            "\"\\u0048\\u004d\\u0041\\u0043\\u002d\\u0053\\u0048\\u0041\\u0032\\u0035\\u0036\"",
        ] {
            assert!(
                matches!(verify_input(record(spelling).as_bytes(), key), VerifyOutcome::Valid),
                "spelling {spelling} must verify"
            );
            assert!(
                matches!(
                    verify_input(record(spelling).as_bytes(), wrong_key),
                    VerifyOutcome::Mismatch
                ),
                "spelling {spelling} under a wrong key must mismatch"
            );
        }

        // Any other decoded string is unsupported — even though this
        // record's tag genuinely matches under HMAC-SHA256 with `key`.
        // Case variants, surrounding whitespace, the empty string and an
        // escaped unsupported name alike, under either key.
        for spelling in [
            "\"HMAC-SHA512\"",
            "\"hmac-sha256\"",
            "\" HMAC-SHA256\"",
            "\"HMAC-SHA256 \"",
            "\"\"",
            "\"HMAC-SHA\\u003512\"",
        ] {
            for k in [key, wrong_key] {
                match verify_input(record(spelling).as_bytes(), k) {
                    VerifyOutcome::Invalid(msg) => {
                        assert!(msg.contains("unsupported"), "{spelling}: {msg}");
                        assert!(msg.contains("HMAC-SHA256"), "{spelling}: {msg}");
                    }
                    other => panic!("spelling {spelling}: expected Invalid, got {other:?}"),
                }
            }
        }

        // Missing and non-string keep their own corruption reasons, never a
        // uniform "unknown algorithm" reading.
        let missing = format!(
            "{{\"format\":1,\"key_id\":\"id\",\"key_version\":1,\"fields\":[\"x\"],\"tag\":\"{tag}\"}}"
        );
        match verify_input(missing.as_bytes(), key) {
            VerifyOutcome::Invalid(msg) => {
                assert!(msg.contains("missing required member \"algorithm\""), "{msg}");
                assert!(!msg.contains("unsupported"), "{msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        for token in ["1", "true", "null", "[\"HMAC-SHA256\"]"] {
            match verify_input(record(token).as_bytes(), key) {
                VerifyOutcome::Invalid(msg) => {
                    assert!(msg.contains("must be a string"), "{token}: {msg}");
                    assert!(!msg.contains("unsupported"), "{token}: {msg}");
                }
                other => panic!("token {token}: expected Invalid, got {other:?}"),
            }
        }
    }

}
