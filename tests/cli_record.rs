//! End-to-end regression tests for the observable result of `authnote sign`.
//!
//! These tests execute the built binary and assert on the exact JSON record a
//! user receives on stdout/stderr, not just on intermediate HMAC values.
//!
//! Expected tags are *golden* values: each was computed independently with
//! Python's hmac/hashlib/struct straight from the format-1 byte contract in
//! README.md (domain separator `authnote-sign-v1`, big-endian u64/u32 length
//! prefixes, raw UTF-8 bytes), never derived from this crate's own HMAC code.
//! A change that breaks the byte encoding and the JSON output in the same way
//! therefore still fails these tests.
//!
//! The tests parse stdout with the small JSON parser below instead of pulling
//! in a third-party dependency, so `Cargo.toml` stays unchanged.

use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// Test harness around the compiled binary.
// ---------------------------------------------------------------------------

fn authnote() -> Command {
    Command::new(env!("CARGO_BIN_EXE_authnote"))
}

/// Run `sign` with `--field` entries appended in the given order.
fn run_sign(key: &str, key_id: &str, version: &str, fields: &[&str]) -> Output {
    let mut cmd = authnote();
    cmd.arg("sign")
        .arg("--key")
        .arg(key)
        .arg("--key-id")
        .arg(key_id)
        .arg("--key-version")
        .arg(version);
    for f in fields {
        cmd.arg("--field").arg(f);
    }
    cmd.output().expect("failed to execute authnote")
}

/// Run `sign` with a raw argument vector (for error-path cases).
fn run_sign_raw(args: &[&str]) -> Output {
    let mut cmd = authnote();
    cmd.arg("sign");
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("failed to execute authnote")
}

// ---------------------------------------------------------------------------
// Minimal JSON parser (objects, arrays, strings, integers, true/false/null).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Json {
    Null,
    // Retained for parser completeness; records carry no boolean values.
    #[allow(dead_code)]
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn parse(s: &str) -> Json {
        let mut p = Parser {
            chars: s.chars().collect(),
            pos: 0,
        };
        p.ws();
        let v = p.value();
        p.ws();
        assert_eq!(p.pos, p.chars.len(), "trailing data after JSON record: {s}");
        v
    }

    fn as_str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("expected JSON string, got {other:?}"),
        }
    }

    fn as_i64(&self) -> i64 {
        match self {
            Json::Num(n) => *n,
            other => panic!("expected JSON number, got {other:?}"),
        }
    }

    fn as_array(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            other => panic!("expected JSON array, got {other:?}"),
        }
    }

    fn as_object(&self) -> &[(String, Json)] {
        match self {
            Json::Obj(o) => o,
            other => panic!("expected JSON object, got {other:?}"),
        }
    }

    fn get(&self, key: &str) -> &Json {
        let obj = self.as_object();
        let idx = obj
            .iter()
            .position(|(k, _)| k == key)
            .unwrap_or_else(|| panic!("missing key {key:?} in {self:?}"));
        &obj[idx].1
    }

    /// Every string value anywhere in the document.
    fn strings(&self, out: &mut Vec<String>) {
        match self {
            Json::Str(s) => out.push(s.clone()),
            Json::Arr(a) => a.iter().for_each(|v| v.strings(out)),
            Json::Obj(o) => o.iter().for_each(|(_, v)| v.strings(out)),
            Json::Null | Json::Bool(_) | Json::Num(_) => {}
        }
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn ws(&mut self) {
        while self.pos < self.chars.len() && self.chars[self.pos].is_whitespace() {
            self.pos += 1;
        }
    }

    fn bump(&mut self) -> char {
        assert!(self.pos < self.chars.len(), "unexpected end of JSON");
        let c = self.chars[self.pos];
        self.pos += 1;
        c
    }

    fn expect(&mut self, want: char) {
        assert!(self.pos < self.chars.len(), "expected {want:?}, found end of JSON");
        let got = self.chars[self.pos];
        assert_eq!(got, want, "expected {want:?} at position {}", self.pos);
        self.pos += 1;
    }

    fn value(&mut self) -> Json {
        self.ws();
        assert!(self.pos < self.chars.len(), "unexpected end of JSON");
        match self.chars[self.pos] {
            '{' => self.object(),
            '[' => self.array(),
            '"' => Json::Str(self.string()),
            't' | 'f' => self.boolean(),
            'n' => self.null(),
            c if c == '-' || c.is_ascii_digit() => self.number(),
            c => panic!("unexpected character {c:?} in JSON"),
        }
    }

    fn object(&mut self) -> Json {
        self.expect('{');
        let mut entries = Vec::new();
        self.ws();
        if self.chars[self.pos] == '}' {
            self.pos += 1;
            return Json::Obj(entries);
        }
        loop {
            self.ws();
            let key = self.string();
            self.ws();
            self.expect(':');
            let val = self.value();
            entries.push((key, val));
            self.ws();
            match self.bump() {
                ',' => continue,
                '}' => break,
                c => panic!("bad object separator {c:?}"),
            }
        }
        Json::Obj(entries)
    }

    fn array(&mut self) -> Json {
        self.expect('[');
        let mut items = Vec::new();
        self.ws();
        if self.chars[self.pos] == ']' {
            self.pos += 1;
            return Json::Arr(items);
        }
        loop {
            items.push(self.value());
            self.ws();
            match self.bump() {
                ',' => continue,
                ']' => break,
                c => panic!("bad array separator {c:?}"),
            }
        }
        Json::Arr(items)
    }

    fn string(&mut self) -> String {
        self.expect('"');
        let mut out = String::new();
        loop {
            match self.bump() {
                '"' => break,
                '\\' => match self.bump() {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hi = self.hex4();
                        let c = if (0xD800..=0xDBFF).contains(&hi) {
                            assert_eq!(self.bump(), '\\');
                            assert_eq!(self.bump(), 'u');
                            let lo = self.hex4();
                            assert!(
                                (0xDC00..=0xDFFF).contains(&lo),
                                "bad low surrogate {lo:x}"
                            );
                            char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                                .expect("bad surrogate pair")
                        } else {
                            char::from_u32(hi).expect("bad unicode escape")
                        };
                        out.push(c);
                    }
                    c => panic!("bad escape \\{c}"),
                },
                // Raw control bytes must not appear unescaped in JSON text.
                c if (c as u32) < 0x20 => panic!("unescaped control character {c:?} in JSON"),
                c => out.push(c),
            }
        }
        out
    }

    fn hex4(&mut self) -> u32 {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.bump();
            v = v * 16 + c.to_digit(16).unwrap_or_else(|| panic!("bad hex digit {c:?}"));
        }
        v
    }

    fn number(&mut self) -> Json {
        let start = self.pos;
        if self.chars[self.pos] == '-' {
            self.pos += 1;
        }
        while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        Json::Num(text.parse().unwrap_or_else(|_| panic!("bad number {text}")))
    }

    fn boolean(&mut self) -> Json {
        if self.chars[self.pos] == 't' {
            for want in "true".chars() {
                self.expect(want);
            }
            Json::Bool(true)
        } else {
            for want in "false".chars() {
                self.expect(want);
            }
            Json::Bool(false)
        }
    }

    fn null(&mut self) -> Json {
        for want in "null".chars() {
            self.expect(want);
        }
        Json::Null
    }
}

// ---------------------------------------------------------------------------
// Record-level assertions shared by every success-path test.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Record {
    raw: Json,
    format: i64,
    algorithm: String,
    key_id: String,
    key_version: i64,
    fields: Vec<String>,
    tag: String,
}

/// Parse the sole JSON record on stdout, enforcing the observable contract:
/// exactly one line, exactly the six documented keys in documented order,
/// format 1, fixed algorithm name, valid version range, 64 lowercase hex tag.
fn parse_single_record(stdout: &[u8]) -> Record {
    let text = std::str::from_utf8(stdout).expect("stdout must be valid UTF-8");
    assert!(text.starts_with('{'), "stdout must start with the JSON object");
    let body = text
        .strip_suffix('\n')
        .expect("stdout must end with exactly one newline");
    assert!(!body.is_empty(), "stdout must contain one JSON record");
    assert!(!body.contains('\n'), "stdout must contain exactly one line");
    assert!(!body.ends_with('\r'), "line must not carry a carriage return");

    let raw = Json::parse(body);
    let keys: Vec<&str> = raw.as_object().iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "format",
            "algorithm",
            "key_id",
            "key_version",
            "fields",
            "tag"
        ],
        "record field structure must stay compatible"
    );

    let fields = raw
        .get("fields")
        .as_array()
        .iter()
        .map(|v| v.as_str().to_string())
        .collect();

    let rec = Record {
        format: raw.get("format").as_i64(),
        algorithm: raw.get("algorithm").as_str().to_string(),
        key_id: raw.get("key_id").as_str().to_string(),
        key_version: raw.get("key_version").as_i64(),
        fields,
        tag: raw.get("tag").as_str().to_string(),
        raw,
    };

    assert_eq!(rec.format, 1, "format must always be 1");
    assert_eq!(rec.algorithm, "HMAC-SHA256");
    assert!(
        (1..=u32::MAX as i64).contains(&rec.key_version),
        "key_version out of range: {}",
        rec.key_version
    );
    assert_eq!(rec.tag.len(), 64, "tag must be 64 hex characters");
    assert!(
        rec.tag
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "tag must be lowercase hex, got {}",
        rec.tag
    );
    rec
}

/// Successful invocation: exit code 0, empty stderr, one valid record whose
/// fields/key-id/version match the inputs and whose tag equals the golden
/// value computed independently of this implementation.
fn expect_signed_record(
    label: &str,
    key: &str,
    key_id: &str,
    version: &str,
    fields: &[&str],
    golden_tag: &str,
) -> Record {
    let out = run_sign(key, key_id, version, fields);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{label}: expected exit 0, got {:?}, stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "{label}: stderr must be empty, got {:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rec = parse_single_record(&out.stdout);
    assert_eq!(rec.tag, golden_tag, "{label}: tag mismatch");
    assert_eq!(rec.key_id, key_id, "{label}: key_id mismatch");
    assert_eq!(
        rec.key_version,
        version.parse::<i64>().unwrap(),
        "{label}: key_version mismatch"
    );
    assert_eq!(
        rec.fields,
        fields.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "{label}: parsed fields must be character-identical to the inputs"
    );

    // The raw key is used only for the MAC: it must never appear as a value
    // anywhere in the record (compared as a whole string, not a substring, so
    // short keys cannot clash with random fragments of the 64-char tag).
    let needle = key.to_lowercase();
    let mut strings = Vec::new();
    rec.raw.strings(&mut strings);
    assert!(
        strings.iter().all(|s| s.to_lowercase() != needle),
        "{label}: raw key material must not be part of the record"
    );
    rec
}

// ---------------------------------------------------------------------------
// Success-path tests.
// ---------------------------------------------------------------------------

#[test]
fn readme_example_matches_published_record() {
    // The exact command and JSON line documented in README.md. The tag is the
    // publicly documented value, so this also pins README/implementation drift.
    let rec = expect_signed_record(
        "readme",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "demo",
        "3",
        &["hello", "世界"],
        "e451500f028e969efb0d6fe533ab40a90d2e8267112cd5c95804d86f7f076d8f",
    );
    assert_eq!(rec.fields, vec!["hello".to_string(), "世界".to_string()]);
}

#[test]
fn unicode_and_json_escapes_round_trip_char_for_char() {
    // One field exercising every escape path alongside raw multibyte text:
    // Chinese, emoji, double quote, backslash, newline, CR, tab, several
    // control characters and DEL. NUL cannot be passed through execve, so the
    // C0 range is covered by 0x01/0x08/0x0c/0x1f plus the dedicated
    // single-character field test below.
    let tricky = "中文🙂\"\\\n\r\t\u{01}\u{08}\u{0c}\u{1f}\u{7f}";
    let out = run_sign(
        "00112233445566778899aabbccddeeff",
        "kid-名字",
        "7",
        &[tricky],
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    let rec = parse_single_record(&out.stdout);

    // Golden tag computed over the *unescaped* original text; if JSON escaping
    // changed the authenticated bytes, this value would not match.
    assert_eq!(
        rec.tag,
        "bfd39e8805a08d6cabbc2570d659bf746e7cbc0f49a714e8e9743eb710e80fac"
    );
    assert_eq!(rec.key_id, "kid-名字");

    // The parsed record text must equal the input character for character.
    assert_eq!(rec.fields.len(), 1);
    assert_eq!(rec.fields[0], tricky);

    // And the wire format must use standard JSON escapes without altering the
    // authenticated original (multibyte text stays as raw UTF-8).
    let raw = std::str::from_utf8(&out.stdout).unwrap();
    assert!(raw.contains("\\\""), "double quote must be escaped");
    assert!(raw.contains("\\\\"), "backslash must be escaped");
    assert!(raw.contains("\\n"), "newline must be escaped");
    assert!(raw.contains("\\r"), "carriage return must be escaped");
    assert!(raw.contains("\\t"), "tab must be escaped");
    assert!(raw.contains("\\u0001"));
    assert!(raw.contains("\\u0008"));
    assert!(raw.contains("\\u000c"));
    assert!(raw.contains("\\u001f"));
    assert!(raw.contains("中文🙂"), "printable Unicode must stay raw UTF-8");
    assert!(raw.contains('\u{7f}'), "DEL is not escaped by format 1 output");

    // The raw key must not appear as a value anywhere in the record.
    let mut strings = Vec::new();
    rec.raw.strings(&mut strings);
    assert!(strings
        .iter()
        .all(|s| s.to_lowercase() != "00112233445566778899aabbccddeeff"));
}

#[test]
fn each_special_character_round_trips_in_its_own_field() {
    let fields = ["\"", "\\", "\n", "\r", "\t", "\u{01}", "🙂"];
    expect_signed_record(
        "escape-fields",
        "aabbccdd",
        "k",
        "2",
        &fields,
        "ab64e8a48c0ff16fd667fb6b22248f67a35e34dcb9f83ff39fafbcfe54906080",
    );
}

#[test]
fn golden_tags_cover_boundaries_and_multibyte_content() {
    // Every tag here is an independent Python HMAC-SHA256 over the format-1
    // encoding documented in README.md.
    let cases: &[(&str, &str, &str, &str, &[&str], &str)] = &[
        // label, key, key-id, version, fields, golden tag
        ("empty-message", "00ff", "id", "1", &[],
            "264a531e2944beb41202f1c1249f2bc1b838f176469a68cdffc484f7ee29b3d6"),
        ("one-empty-field", "00ff", "id", "1", &[""],
            "1403803e197b14216fd9d51ff583dfb5eaba67aab92e0e96ba5f873bbeeee164"),
        ("two-empty-fields", "00ff", "id", "1", &["", ""],
            "a4e5c84fdc0ac3544b35c7af1bcb41c26fa10ea49b75d67a1c7900ad44f11aab"),
        ("split-ab-c", "00ff", "id", "1", &["ab", "c"],
            "7f9c51979f06825d505f13d9f028317e2ebe39671a3fafef90a18d81066fb570"),
        ("split-a-bc", "00ff", "id", "1", &["a", "bc"],
            "79184921ce69b3b60b371655d9da69baea3199fb09d30c4652f8caf6c2d17028"),
        ("joined-abc", "00ff", "id", "1", &["abc"],
            "f0aca403b09203cde743f4269fca659bf2246a18851374cbb02869587e6f2970"),
        ("ab-plus-empty", "00ff", "id", "1", &["ab", ""],
            "561a59e16a1b15534659d874871375dea9415c34ee7aabcb6e3b2f6f7946fba1"),
        ("a-b-empty", "00ff", "id", "1", &["a", "b", ""],
            "35cdb57894413bb0f69df2f26811e6351d2878b5fc71c2f017c73b4fb13cee7c"),
        ("single-ab", "00ff", "id", "1", &["ab"],
            "c4e0c0326796572ca45896897a0fafb9dcf17d2b5078dc241b0ff5c3a71ec8a9"),
        ("multibyte-max-version", "deadbeef", "id", "4294967295", &["世界🙂"],
            "2372588cc44141e818bc0f7a6ca7c09e6d87af2cfc364696e30c4c8653b9c408"),
        ("three-byte-char", "00ff", "id", "1", &["é"],
            "0a0d1264786153d4cee915619413d30a55e0886069d13a4aaccb0290bd20b8de"),
        ("four-byte-char", "00ff", "id", "1", &["🙂"],
            "e1f3099963da5e322c92cfb7a6c1c55e912ddc5606abe2273439ddf116dad624"),
        ("unicode-key-id-and-fields", &"aa".repeat(32), "密钥", "42", &["🙂🙂"],
            "80a2dfd92f3a757226c7986f732ad4632a034a87a5426126735ef511eeadff0e"),
        ("escaped-key-id", "00ff", "a\"b\nc", "1", &["q"],
            "00061a96ea7d09a5179fc96e43f700b3fe1ddbe13c7d3747b1a4f72718042be7"),
        ("dup-x-x", "0102", "id", "1", &["x", "x"],
            "9dc97338f638b83cc7d245e798a0ee1b54596321356b5595b9a83a1f750c8856"),
        ("single-x-0102", "0102", "id", "1", &["x"],
            "9b326498fb6eb680d2790d03c72fdc548767d65e9aef2d20a5b817c58a802bdc"),
        ("order-a-b", "0102", "id", "1", &["a", "b"],
            "75918dc7d9b81f438215918f8d02a8c8431d08fc6b8d88b5ef15a895b0029cf5"),
        ("order-b-a", "0102", "id", "1", &["b", "a"],
            "5378141a4fe25376cee77b776460d662fea0d67d56b7b8cf95a3e105470c3ef7"),
        ("order-x-y-x", "00ff", "id", "1", &["x", "y", "x"],
            "7abf79d29bbc9944d3b5712ff5a137a057700810ecb57694243c86a5a7532358"),
        ("order-x-x-y", "00ff", "id", "1", &["x", "x", "y"],
            "47d0d033362b28a7f66de34307032abb9a380dffca190c11e5a35aaa203641c6"),
    ];
    for (label, key, key_id, version, fields, golden) in cases {
        expect_signed_record(label, key, key_id, version, fields, golden);
    }
}

/// Run the same signing twice and return both records' parsed form plus the
/// exact stdout bytes, for determinism comparisons.
fn sign_twice(key: &str, key_id: &str, version: &str, fields: &[&str]) -> (Record, Record, Vec<u8>, Vec<u8>) {
    let out1 = run_sign(key, key_id, version, fields);
    let out2 = run_sign(key, key_id, version, fields);
    assert_eq!(out1.status.code(), Some(0));
    assert_eq!(out2.status.code(), Some(0));
    assert!(out1.stderr.is_empty() && out2.stderr.is_empty());
    (
        parse_single_record(&out1.stdout),
        parse_single_record(&out2.stdout),
        out1.stdout,
        out2.stdout,
    )
}

#[test]
fn output_is_deterministic_and_key_hex_case_is_insensitive() {
    // Same actual key + same message must produce byte-identical output.
    let (r1, r2, raw1, raw2) = sign_twice("00ff", "id", "1", &["x"]);
    assert_eq!(raw1, raw2, "repeated signing must be byte-identical");
    assert_eq!(r1.tag, r2.tag);

    // The case of the hexadecimal key letters must not change the tag.
    let golden = "2ebc5f9c2a6edd8a4b103dd6262003e5a521f3984ee1d202a63216ef10d0bf32";
    for key in ["00ff", "00FF", "00fF", "00Ff"] {
        expect_signed_record("key-case", key, "id", "1", &["x"], golden);
    }
}

#[test]
fn tag_is_bound_to_key_id_version_and_key() {
    // Golden tag for ("00ff", "id", 1, ["x"]); the three variants each have
    // their own independently computed golden value.
    let base = expect_signed_record(
        "base",
        "00ff", "id", "1", &["x"],
        "2ebc5f9c2a6edd8a4b103dd6262003e5a521f3984ee1d202a63216ef10d0bf32",
    );
    let other_id = expect_signed_record(
        "key-id",
        "00ff", "id2", "1", &["x"],
        "0ce18fc4c634e836848081defe3270a74e4357912baab995c1568090d0c081b7",
    );
    let other_version = expect_signed_record(
        "version",
        "00ff", "id", "2", &["x"],
        "5bb5cfb53a0ba13aa4d014918ea99b838e0846272a5737fbfef73397737254e5",
    );
    let other_key = expect_signed_record(
        "key",
        "ff00", "id", "1", &["x"],
        "9757269a5b500da6ad908822ac00a4204c87f5e504b92fb58d92094c30314dc6",
    );
    assert_ne!(base.tag, other_id.tag);
    assert_ne!(base.tag, other_version.tag);
    assert_ne!(base.tag, other_key.tag);
    // Fields are identical here; it is the binding metadata/key that moved.
    assert_eq!(base.fields, other_id.fields);
    assert_eq!(other_id.key_id, "id2");
    assert_eq!(other_version.key_version, 2);
}

#[test]
fn zero_fields_and_one_empty_field_are_distinct_records() {
    let empty = expect_signed_record(
        "zero-fields",
        "00ff", "id", "1", &[],
        "264a531e2944beb41202f1c1249f2bc1b838f176469a68cdffc484f7ee29b3d6",
    );
    let one_empty = expect_signed_record(
        "one-empty",
        "00ff", "id", "1", &[""],
        "1403803e197b14216fd9d51ff583dfb5eaba67aab92e0e96ba5f873bbeeee164",
    );
    // Both the field array AND the tag must distinguish the two records.
    assert_ne!(empty.fields, one_empty.fields);
    assert_eq!(empty.fields.len(), 0);
    assert_eq!(one_empty.fields, vec![String::new()]);
    assert_ne!(empty.tag, one_empty.tag);
}

#[test]
fn duplicate_fields_are_preserved_in_order_and_swaps_change_the_record() {
    // ["x","x"] keeps both entries, in order; it is not the same record as ["x"].
    let dup = expect_signed_record(
        "dup",
        "0102", "id", "1", &["x", "x"],
        "9dc97338f638b83cc7d245e798a0ee1b54596321356b5595b9a83a1f750c8856",
    );
    assert_eq!(dup.fields, vec!["x".to_string(), "x".to_string()]);
    let single = expect_signed_record(
        "single",
        "0102", "id", "1", &["x"],
        "9b326498fb6eb680d2790d03c72fdc548767d65e9aef2d20a5b817c58a802bdc",
    );
    assert_ne!(dup.fields, single.fields);
    assert_ne!(dup.tag, single.tag);

    // Swapping two distinct fields changes fields and tag together; neither
    // ordering is allowed to carry the original message's tag.
    let ab = expect_signed_record(
        "ab",
        "0102", "id", "1", &["a", "b"],
        "75918dc7d9b81f438215918f8d02a8c8431d08fc6b8d88b5ef15a895b0029cf5",
    );
    let ba = expect_signed_record(
        "ba",
        "0102", "id", "1", &["b", "a"],
        "5378141a4fe25376cee77b776460d662fea0d67d56b7b8cf95a3e105470c3ef7",
    );
    assert_ne!(ab.fields, ba.fields);
    assert_ne!(ab.tag, ba.tag);

    let xyx = expect_signed_record(
        "xyx",
        "00ff", "id", "1", &["x", "y", "x"],
        "7abf79d29bbc9944d3b5712ff5a137a057700810ecb57694243c86a5a7532358",
    );
    let xxy = expect_signed_record(
        "xxy",
        "00ff", "id", "1", &["x", "x", "y"],
        "47d0d033362b28a7f66de34307032abb9a380dffca190c11e5a35aaa203641c6",
    );
    assert_ne!(xyx.fields, xxy.fields);
    assert_ne!(xyx.tag, xxy.tag);
}

#[test]
fn multiple_fields_never_degenerate_to_plain_concatenation() {
    // Each row lists the concatenation of its fields: rows sharing the same
    // joined text must still produce distinct records thanks to the length
    // prefixes. Empty fields at either boundary are part of the message too.
    let variants: &[(&str, &[&str], &str, &str)] = &[
        // label, fields, golden tag, concatenated field text
        ("ab-c", &["ab", "c"], "7f9c51979f06825d505f13d9f028317e2ebe39671a3fafef90a18d81066fb570", "abc"),
        ("a-bc", &["a", "bc"], "79184921ce69b3b60b371655d9da69baea3199fb09d30c4652f8caf6c2d17028", "abc"),
        ("abc", &["abc"], "f0aca403b09203cde743f4269fca659bf2246a18851374cbb02869587e6f2970", "abc"),
        ("ab-empty", &["ab", ""], "561a59e16a1b15534659d874871375dea9415c34ee7aabcb6e3b2f6f7946fba1", "ab"),
        ("empty-ab", &["", "ab"], "0ef917e43ad6fdd84b453b1c69d78d779a4be2b3cf2b3e20f8b61a6d8fcde7c3", "ab"),
    ];
    let mut tags = std::collections::HashSet::new();
    let mut field_sets = std::collections::HashSet::new();
    for (label, fields, golden, joined) in variants {
        let rec = expect_signed_record(label, "00ff", "id", "1", fields, golden);
        assert_eq!(
            rec.fields.concat(),
            joined.to_string(),
            "{label}: concatenated field text mismatch"
        );
        tags.insert(rec.tag.clone());
        field_sets.insert(format!("{:?}", rec.fields));
    }
    assert_eq!(tags.len(), variants.len(), "all splittings must have distinct tags");
    assert_eq!(field_sets.len(), variants.len());
}

#[test]
fn byte_length_not_character_count_is_authenticated() {
    // "世界🙂" is 3 characters but 10 UTF-8 bytes (3+3+4); "密钥" is 2
    // characters but 6 bytes. The golden tags were computed over byte lengths,
    // so an implementation that length-prefixes character counts cannot match.
    expect_signed_record(
        "multibyte-fields",
        "deadbeef", "id", "4294967295", &["世界🙂"],
        "2372588cc44141e818bc0f7a6ca7c09e6d87af2cfc364696e30c4c8653b9c408",
    );
    expect_signed_record(
        "multibyte-key-id",
        &"aa".repeat(32), "密钥", "42", &["🙂🙂"],
        "80a2dfd92f3a757226c7986f732ad4632a034a87a5426126735ef511eeadff0e",
    );
}

// ---------------------------------------------------------------------------
// Failure-path tests.
// ---------------------------------------------------------------------------

fn expect_usage_error(args: &[&str]) -> String {
    let out = run_sign_raw(args);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for args {args:?}, got {:?}",
        out.status.code()
    );
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty on error, got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8(out.stderr).expect("stderr must be valid UTF-8");
    assert!(!stderr.trim().is_empty(), "stderr must explain the problem");
    stderr
}

#[test]
fn invalid_keys_fail_with_exit_2_and_empty_stdout() {
    // Odd-length hexadecimal.
    expect_usage_error(&["--key", "abc", "--key-id", "id", "--key-version", "1"]);
    // Non-hex characters.
    expect_usage_error(&["--key", "zz", "--key-id", "id", "--key-version", "1"]);
    // Empty key.
    expect_usage_error(&["--key", "", "--key-id", "id", "--key-version", "1"]);
    // Key option given without a value.
    expect_usage_error(&["--key", "--key-id", "id", "--key-version", "1"]);
}

#[test]
fn missing_required_parameters_fail_with_exit_2() {
    expect_usage_error(&[]);
    expect_usage_error(&["--key-id", "id", "--key-version", "1"]);
    expect_usage_error(&["--key", "00ff", "--key-version", "1"]);
    expect_usage_error(&["--key", "00ff", "--key-id", "id"]);
    // Invalid values are usage errors as well.
    expect_usage_error(&["--key", "00ff", "--key-id", "id", "--key-version", "0"]);
    expect_usage_error(&[
        "--key", "00ff", "--key-id", "id", "--key-version", "4294967296",
    ]);
    expect_usage_error(&["--key", "00ff", "--key-id", "", "--key-version", "1"]);
    // Duplicate / unknown options.
    expect_usage_error(&[
        "--key", "aa", "--key", "bb",
        "--key-id", "id", "--key-version", "1",
    ]);
    expect_usage_error(&[
        "--key", "00ff", "--key-id", "id", "--key-version", "1", "--bogus", "x",
    ]);
}

#[test]
fn error_messages_never_echo_the_key() {
    let secret = "deadbeefcafebabedeadbeefcafebabe";

    // Bad key itself: the rejected key value must not be quoted back.
    let stderr = expect_usage_error(&[
        "--key", "abczzz", "--key-id", "id", "--key-version", "1",
    ]);
    assert!(!stderr.contains("abczzz"), "stderr echoed the key: {stderr}");

    // Failures on *other* parameters while a valid key is present must not
    // leak it either.
    let stderr = expect_usage_error(&[
        "--key", secret, "--key-id", "id", "--key-version", "0",
    ]);
    assert!(!stderr.contains(secret), "stderr echoed the key: {stderr}");

    let stderr = expect_usage_error(&[
        "--key", secret, "--key-id", "", "--key-version", "1",
    ]);
    assert!(!stderr.contains(secret), "stderr echoed the key: {stderr}");

    let stderr = expect_usage_error(&[
        "--key", secret, "--key", "00ff",
        "--key-id", "id", "--key-version", "1",
    ]);
    assert!(!stderr.contains(secret), "stderr echoed the key: {stderr}");

    // Uppercase spelling must not leak through either.
    let loud = secret.to_uppercase();
    let stderr = expect_usage_error(&[
        "--key", &loud, "--key-id", "id", "--key-version", "9999999999",
    ]);
    assert!(
        !stderr.to_lowercase().contains(secret),
        "stderr echoed the key: {stderr}"
    );
}

#[test]
fn unrecognized_arguments_are_never_echoed() {
    let secret = "deadbeefcafebabedeadbeefcafebabe";

    // The scenario from the field: `--key-id` is given without a value, so it
    // consumes `--key` as its value, and the actual key string that follows
    // becomes an unrecognized argument. The error must not repeat it.
    let stderr = expect_usage_error(&["--key-id", "--key", secret, "--key-version", "1"]);
    assert!(
        !stderr.contains(secret),
        "stderr echoed an unrecognized argument that was actually the key: {stderr}"
    );

    // Unknown option in the separate-value form.
    let stderr = expect_usage_error(&[
        "--key", "00ff", "--key-id", "id", "--key-version", "1", "--bogus", secret,
    ]);
    assert!(!stderr.contains(secret), "stderr echoed input: {stderr}");

    // Unknown option in the --opt=value form: neither name nor value may leak.
    let stderr = expect_usage_error(&[
        "--key", "00ff", "--key-id", "id", "--key-version", "1",
        &format!("--bogus={secret}"),
    ]);
    assert!(!stderr.contains(secret), "stderr echoed input: {stderr}");
    assert!(!stderr.contains("--bogus"), "stderr echoed input: {stderr}");

    // A bare positional argument must not be echoed either.
    let stderr = expect_usage_error(&[
        "--key", "00ff", "--key-id", "id", "--key-version", "1", secret,
    ]);
    assert!(!stderr.contains(secret), "stderr echoed input: {stderr}");

    // A key given via --key=HEX must stay secret when a *later* argument fails.
    let stderr = expect_usage_error(&[
        &format!("--key={secret}"), "--key-id", "id", "--key-version", "1", "--bogus",
    ]);
    assert!(!stderr.contains(secret), "stderr echoed the key: {stderr}");
}

#[cfg(unix)]
#[test]
fn non_utf8_arguments_fail_with_exit_2_not_a_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // 0xFF is never valid UTF-8.
    let bad = OsStr::from_bytes(b"\xff\xfe");

    // An undecodable argument anywhere in the sign command line.
    let out = authnote()
        .arg("sign")
        .arg("--key")
        .arg("00ff")
        .arg("--key-id")
        .arg("id")
        .arg("--key-version")
        .arg("1")
        .arg(bad)
        .output()
        .expect("failed to execute authnote");
    assert_eq!(out.status.code(), Some(2), "got {:?}", out.status.code());
    assert!(out.stdout.is_empty(), "stdout must be empty on error");
    let stderr = String::from_utf8(out.stderr).expect("stderr must be valid UTF-8");
    assert!(!stderr.trim().is_empty(), "stderr must explain the problem");
    assert!(
        !stderr.contains('\u{fffd}'),
        "stderr must not contain replacement characters from lossy decoding: {stderr}"
    );

    // An undecodable argument before any subcommand fails the same way.
    let out = authnote()
        .arg(bad)
        .output()
        .expect("failed to execute authnote");
    assert_eq!(out.status.code(), Some(2), "got {:?}", out.status.code());
    assert!(out.stdout.is_empty(), "stdout must be empty on error");
    assert!(!out.stderr.is_empty(), "stderr must explain the problem");
}
