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

/// Run `verify --key <key>` feeding `input` to standard input.
fn run_verify(key: &str, input: &[u8]) -> Output {
    let mut cmd = authnote();
    cmd.arg("verify").arg("--key").arg(key);
    use std::io::Write;
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn authnote");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("failed to write record to stdin");
    child.wait_with_output().expect("failed to await authnote")
}

/// Run `verify` with raw arguments and stdin (for option-error cases).
fn run_verify_raw(args: &[&str], input: &[u8]) -> Output {
    let mut cmd = authnote();
    cmd.arg("verify");
    for a in args {
        cmd.arg(a);
    }
    use std::io::Write;
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn authnote");
    // Every caller here drives an error path that exits before reading stdin
    // (a malformed option), so the child may already be gone when we write; a
    // BrokenPipe then simply reflects that early exit and must not fail the
    // test. The outcome is still pinned by the exit code / stdout / stderr
    // assertions after reaping the child.
    if let Err(e) = child.stdin.take().unwrap().write_all(input) {
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe,
            "unexpected stdin write error: {e}"
        );
    }
    child.wait_with_output().expect("failed to await authnote")
}

/// Sign a record and return its exact stdout bytes (including the newline).
fn sign_record_bytes(key: &str, key_id: &str, version: &str, fields: &[&str]) -> Vec<u8> {
    run_sign(key, key_id, version, fields).stdout
}

// ---------------------------------------------------------------------------
// verify: success path
// ---------------------------------------------------------------------------

#[test]
fn verify_accepts_the_record_sign_produces() {
    let key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    let record = sign_record_bytes(key, "demo", "3", &["hello", "世界"]);
    let out = run_verify(key, &record);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "stderr must be empty, got {:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
}

#[test]
fn verify_tolerates_reserialization_reordering_and_whitespace() {
    let key = "00112233445566778899aabbccddeeff";
    let record = sign_record_bytes(key, "kid-名字", "7", &["中文🙂", "x y"]);

    // Parse, then emit pretty JSON with members in reverse order.
    let body = std::str::from_utf8(&record).unwrap().trim_end_matches('\n');
    let parsed = Json::parse(body);
    let obj = parsed.as_object();
    let mut reordered = String::from("{\n");
    for (i, (k, v)) in obj.iter().rev().enumerate() {
        if i > 0 {
            reordered.push_str(",\n");
        }
        reordered.push_str(&format!("  {k:?}: "));
        reordered.push_str(&json_value_to_text(v));
    }
    reordered.push_str("\n}");
    let padded = format!("  \t\n{reordered}\r\n  ");

    let out = run_verify(key, padded.as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(out.stderr.is_empty());
}

/// Render a parsed Json back into compact JSON (test helper; records contain
/// only objects/arrays/strings/integers).
fn json_value_to_text(v: &Json) -> String {
    fn escape(s: &str) -> String {
        let mut out = String::from("\"");
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
        out.push('"');
        out
    }
    match v {
        Json::Str(s) => escape(s),
        Json::Num(n) => n.to_string(),
        Json::Arr(a) => format!(
            "[{}]",
            a.iter().map(json_value_to_text).collect::<Vec<_>>().join(",")
        ),
        Json::Obj(o) => format!(
            "{{{}}}",
            o.iter()
                .map(|(k, v)| format!("{}:{}", escape(k), json_value_to_text(v)))
                .collect::<Vec<_>>().join(",")
        ),
        other => panic!("unexpected value {other:?}"),
    }
}

#[test]
fn verify_distinct_encodings_and_unicode_escapes() {
    let key = "00ff";
    // Zero fields vs one empty field each verify with their own records.
    let zero = sign_record_bytes(key, "id", "1", &[]);
    let one_empty = sign_record_bytes(key, "id", "1", &[""]);
    assert_eq!(run_verify(key, &zero).status.code(), Some(0));
    assert_eq!(run_verify(key, &one_empty).status.code(), Some(0));

    // A record whose Chinese text is written using \u escapes still verifies:
    // verification runs over the decoded text, not the raw JSON spelling.
    let rec = sign_record_bytes(key, "id", "1", &["世界"]);
    let body = std::str::from_utf8(&rec).unwrap();
    let escaped = body.replace("世界", "\\u4e16\\u754c");
    let out = run_verify(key, escaped.as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"{\"valid\":true}\n");

    // Uppercase tag hex is accepted and still yields valid.
    let body = String::from_utf8(rec).unwrap();
    let parsed = Json::parse(body.trim_end_matches('\n'));
    let upper_obj: Vec<(String, Json)> = parsed
        .as_object()
        .iter()
        .map(|(k, v)| {
            if k == "tag" {
                (k.clone(), Json::Str(v.as_str().to_uppercase()))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    let rebuilt = json_value_to_text(&Json::Obj(upper_obj)) + "\n";
    let out = run_verify(key, rebuilt.as_bytes());
    assert_eq!(out.status.code(), Some(0));
}

// ---------------------------------------------------------------------------
// verify: mismatch path (exit 1, {"valid":false})
// ---------------------------------------------------------------------------

#[test]
fn verify_wrong_key_and_tampered_fields_exit_1() {
    let key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    let record = sign_record_bytes(key, "demo", "3", &["hello", "世界"]);

    // Wrong key: structurally fine, just doesn't authenticate.
    let out = run_verify("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c", &record);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    assert_eq!(out.stdout, b"{\"valid\":false}\n");

    // Tampered field content / key id / version: each keeps legal JSON.
    let body = std::str::from_utf8(&record).unwrap();
    let variants = [
        body.replace("hello", "hellp"),
        body.replace("\"demo\"", "\"demo2\""),
        body.replace("\"key_version\":3", "\"key_version\":4"),
    ];
    for rec_text in variants {
        let out = run_verify(key, rec_text.as_bytes());
        assert_eq!(
            out.status.code(),
            Some(1),
            "expected mismatch, stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":false}\n");
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn verify_crossing_empty_field_encodings_fails() {
    let key = "00ff";
    let zero = sign_record_bytes(key, "id", "1", &[]);
    let one_empty = sign_record_bytes(key, "id", "1", &[""]);

    // Put the empty-field record's tag onto the zero-field record.
    let zero_obj = Json::parse(std::str::from_utf8(&zero).unwrap().trim_end_matches('\n'));
    let empty_tag = Json::parse(std::str::from_utf8(&one_empty).unwrap().trim_end_matches('\n'))
        .get("tag")
        .as_str()
        .to_string();
    let crossed: Vec<(String, Json)> = zero_obj
        .as_object()
        .iter()
        .map(|(k, v)| {
            if k == "tag" {
                (k.clone(), Json::Str(empty_tag.clone()))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    let out = run_verify(key, (json_value_to_text(&Json::Obj(crossed)) + "\n").as_bytes());
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"{\"valid\":false}\n");
}

// ---------------------------------------------------------------------------
// verify: invalid record / invocation path (exit 2, empty stdout)
// ---------------------------------------------------------------------------

fn expect_verify_invalid(input: &[u8], args: &[&str]) -> String {
    let out = run_verify_raw(args, input);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2, stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "stdout must be empty on exit 2");
    let stderr = String::from_utf8(out.stderr).expect("stderr must be UTF-8");
    assert!(!stderr.trim().is_empty(), "stderr must explain the problem");
    stderr
}

#[test]
fn verify_rejects_multiple_records_and_trailing_garbage() {
    let key = "00ff";
    let rec = sign_record_bytes(key, "id", "1", &["x"]);

    let mut two = rec.clone();
    two.extend_from_slice(&rec);
    expect_verify_invalid(&two, &["--key", key]);

    let mut with_word = rec.clone();
    with_word.extend_from_slice(b" x");
    expect_verify_invalid(&with_word, &["--key", key]);

    let mut with_num = rec.clone();
    with_num.extend_from_slice(b"42");
    expect_verify_invalid(&with_num, &["--key", key]);

    expect_verify_invalid(b"", &["--key", key]);
    expect_verify_invalid(b"   \n\t", &["--key", key]);
}

#[test]
fn verify_rejects_corrupt_and_ill_typed_records() {
    let key = "00ff";
    let bad: &[&[u8]] = &[
        b"{",
        b"[]",
        b"\"x\"",
        b"42",
        br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":["x"]}"#,
        br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"","key_version":1,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":0,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":4294967296,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[1],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        br#"{"format":1,"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"00"}"#,
        br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}"#,
    ];
    for rec in bad {
        expect_verify_invalid(rec, &["--key", key]);
    }

    // Non-UTF-8 input.
    expect_verify_invalid(b"\xff\xff", &["--key", key]);
}

#[test]
fn verify_reports_unsupported_format_and_algorithm_explicitly() {
    let key = "00ff";
    let tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let f2 = format!(
        r#"{{"format":2,"algorithm":"HMAC-SHA256","key_id":"id","key_version":1,"fields":[],"tag":"{tag}"}}"#
    );
    let a2 = format!(
        r#"{{"format":1,"algorithm":"HMAC-SHA512","key_id":"id","key_version":1,"fields":[],"tag":"{tag}"}}"#
    );
    for rec in [f2, a2] {
        let stderr = expect_verify_invalid(rec.as_bytes(), &["--key", key]);
        assert!(
            stderr.to_lowercase().contains("unsupported"),
            "must explicitly say unsupported: {stderr}"
        );
    }
}

#[test]
fn verify_option_errors_match_sign_and_never_echo_secrets() {
    let key = "00ff";
    let rec = sign_record_bytes(key, "id", "1", &["x"]);
    let secret = "deadbeefcafebabedeadbeefcafebabe";

    expect_verify_invalid(&rec, &[]); // missing --key
    expect_verify_invalid(&rec, &["--key"]); // missing value
    expect_verify_invalid(&rec, &["--key", "abc"]); // odd hex
    expect_verify_invalid(&rec, &["--key", "zz"]); // bad hex
    expect_verify_invalid(&rec, &["--key", key, "--key", key]); // duplicate
    expect_verify_invalid(&rec, &["--key", key, "--bogus", "x"]); // unknown
    expect_verify_invalid(&rec, &["--key=zz"]); // inline bad hex

    // A bad key value must not be echoed.
    let stderr = expect_verify_invalid(&rec, &["--key", "abczz"]);
    assert!(!stderr.contains("abczz"), "stderr echoed the key: {stderr}");

    // A valid key on a later failing option must not leak either.
    let stderr = expect_verify_invalid(&rec, &["--key", secret, "--bogus", "x"]);
    assert!(!stderr.contains(secret), "stderr echoed the key: {stderr}");
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
// Option spelling: `--name value` vs `--name=value` (freely mixed).
//
// Every sign option accepts both spellings and they are the *same*
// invocation: the same key, key id, version and in-order fields must produce a
// byte-identical record and tag whether each option is written separated,
// inline with '=', or alternating. Golden tags below are independently
// computed with Python's hmac/hashlib/struct over the format-1 contract in
// README.md, never taken from this crate's own HMAC code.
// ---------------------------------------------------------------------------

/// Assert that every argv spelling of one invocation exits 0 with empty
/// stderr and byte-identical stdout, then parse and return the shared record
/// together with its exact stdout bytes.
fn expect_equivalent_spellings(label: &str, forms: &[&[&str]]) -> (Record, Vec<u8>) {
    let mut stdout: Option<Vec<u8>> = None;
    for (index, args) in forms.iter().enumerate() {
        let out = run_sign_raw(args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{label} form {index}: expected exit 0, stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.stderr.is_empty(),
            "{label} form {index}: stderr must be empty, got {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        if let Some(prev) = &stdout {
            assert_eq!(
                prev,
                &out.stdout,
                "{label} form {index}: the two spellings must produce byte-identical records"
            );
        } else {
            stdout = Some(out.stdout);
        }
    }
    let bytes = stdout.expect("at least one spelling must be provided");
    (parse_single_record(&bytes), bytes)
}

#[test]
fn separated_equals_and_mixed_spellings_produce_identical_records() {
    // The same invocation written three ways: every option separated, every
    // option inline with '=', and the two spellings alternating. The fields
    // exercise Chinese, a real newline, leading/trailing whitespace, embedded
    // '=' (a=b=c), a repeated value and a trailing empty field.
    let separated: &[&str] = &[
        "--key", "00ff", "--key-id", "id", "--key-version", "1",
        "--field", "世界",
        "--field", "\n换行 ",
        "--field", " a=b=c ",
        "--field", "x",
        "--field", "x",
        "--field", "",
    ];
    let inline: &[&str] = &[
        "--key=00ff", "--key-id=id", "--key-version=1",
        "--field=世界",
        "--field=\n换行 ",
        "--field= a=b=c ",
        "--field=x",
        "--field=x",
        "--field=",
    ];
    let mixed: &[&str] = &[
        "--key=00ff", "--key-id", "id", "--key-version=1",
        "--field", "世界",
        "--field=\n换行 ",
        "--field", " a=b=c ",
        "--field=x",
        "--field", "x",
        "--field=",
    ];
    let (rec, raw) =
        expect_equivalent_spellings("all-four-options", &[separated, inline, mixed]);

    // Independent Python golden over the format-1 encoding of these inputs.
    assert_eq!(
        rec.tag,
        "711be5386282d260dc10332d4a7677e3af3906eeff7ae12b2d0fe7b25ea18f10"
    );
    assert_eq!(rec.key_id, "id");
    assert_eq!(rec.key_version, 1);
    assert_eq!(
        rec.fields,
        vec![
            "世界".to_string(),
            "\n换行 ".to_string(),
            " a=b=c ".to_string(),
            "x".to_string(),
            "x".to_string(),
            String::new(),
        ]
    );
    // Mixing spellings neither reorders fields, merges the duplicate "x", nor
    // drops the trailing empty field: all six survive in argv order.
    assert_eq!(rec.fields.len(), 6);

    // The whitespace and the embedded '=' survive on the wire untrimmed.
    let text = String::from_utf8(raw).unwrap();
    assert!(text.contains("\" a=b=c \""), "surrounding whitespace must be kept: {text}");

    // The actual key feeds only the MAC; it is not a record value.
    let mut strings = Vec::new();
    rec.raw.strings(&mut strings);
    assert!(
        strings.iter().all(|s| s != "00ff"),
        "the raw key must not appear as a record value: {strings:?}"
    );
}

#[test]
fn value_whose_text_is_an_option_name_is_kept_as_a_value() {
    // In the separated spelling the argument immediately after an option is
    // its value with no "--"-prefix special-casing: text literally equal to
    // "--key"/"--field" stays a key id/field. The '=' spelling is identical.
    let separated: &[&str] = &[
        "--key", "00ff", "--key-id", "--key", "--key-version", "1",
        "--field", "--field",
    ];
    let inline: &[&str] = &[
        "--key=00ff", "--key-id=--key", "--key-version=1", "--field=--field",
    ];
    let (rec, _) = expect_equivalent_spellings("option-looking-value", &[separated, inline]);
    assert_eq!(
        rec.tag,
        "c7fb9238c7ccf06fc8130c6f94f5b6547c9018d93711db581c95e9f6e9c1937d"
    );
    assert_eq!(rec.key_id, "--key");
    assert_eq!(rec.fields, vec!["--field".to_string()]);

    // A run of option-looking field values (including one with embedded '=')
    // is kept verbatim and in order under both spellings.
    let sep: &[&str] = &[
        "--key", "a1b2", "--key-id", "id", "--key-version", "1",
        "--field", "--key",
        "--field", "--field",
        "--field", "--key-id",
        "--field", "k=v=w",
    ];
    let eq: &[&str] = &[
        "--key=a1b2", "--key-id=id", "--key-version=1",
        "--field=--key", "--field=--field", "--field=--key-id", "--field=k=v=w",
    ];
    let (rec, _) = expect_equivalent_spellings("many-option-looking-fields", &[sep, eq]);
    assert_eq!(
        rec.tag,
        "351219ac3a2d3442243a9261f015b29b385ee54fd7b168be7a40220edef73698"
    );
    assert_eq!(
        rec.fields,
        vec![
            "--key".to_string(),
            "--field".to_string(),
            "--key-id".to_string(),
            "k=v=w".to_string(),
        ]
    );

    // A trailing "--key" consumed as a field value (the real key was supplied
    // inline earlier) must neither be re-parsed as the key option nor error.
    let trailing: &[&str] = &[
        "--key=00ff", "--key-id", "id", "--key-version=1",
        "--field", "a", "--field", "b", "--field", "--key",
    ];
    let out = run_sign_raw(trailing);
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    let rec3 = parse_single_record(&out.stdout);
    assert_eq!(
        rec3.fields,
        vec!["a".to_string(), "b".to_string(), "--key".to_string()]
    );
    assert_eq!(
        rec3.tag,
        "70f0518fdcd556326c82e028caff3a5d11cc1e69e40f093a4767bfe94393f12d"
    );
}

#[test]
fn inline_value_splits_on_the_first_equals_only() {
    // With '--opt=value' everything after the FIRST '=' is the value; later
    // '=' characters remain part of it.
    let sep: &[&str] = &[
        "--key", "00ff", "--key-id", "id", "--key-version", "1", "--field", "a=b=c",
    ];
    let inline: &[&str] = &[
        "--key=00ff", "--key-id=id", "--key-version=1", "--field=a=b=c",
    ];
    let (rec, raw) = expect_equivalent_spellings("field-a=b=c", &[sep, inline]);
    assert_eq!(rec.fields, vec!["a=b=c".to_string()]);
    assert_eq!(
        rec.tag,
        "be789c90ecf9d3981f1d5be9bea6497d2ce8ed92faedb4e6e3e35cb3498f1856"
    );
    // Both '=' characters survive on the wire.
    assert!(String::from_utf8(raw).unwrap().contains("\"a=b=c\""));

    // A key id containing '=' and a field that *starts* with '=':
    // "--field==lead" is option --key with value "=lead" (the second '=' is
    // data).
    let sep: &[&str] = &[
        "--key", "00ff", "--key-id", "a=b", "--key-version", "1", "--field", "=lead",
    ];
    let inline: &[&str] = &[
        "--key=00ff", "--key-id=a=b", "--key-version=1", "--field==lead",
    ];
    let (rec, _) = expect_equivalent_spellings("equals-inside-values", &[sep, inline]);
    assert_eq!(rec.key_id, "a=b");
    assert_eq!(rec.fields, vec!["=lead".to_string()]);
    assert_eq!(
        rec.tag,
        "8e349e5759f1cea7b3df1076fa6cb9a69f476674e2f2d754d744c7bc81634859"
    );
}

#[test]
fn chinese_newline_and_surrounding_whitespace_are_identical_in_both_spellings() {
    const WS: &str = "  首尾空白\t";
    let separated: &[&str] = &[
        "--key", "deadbeef", "--key-id", "密钥-名", "--key-version", "42",
        "--field", "世界", "--field", WS, "--field", "",
    ];
    let inline: &[&str] = &[
        "--key=deadbeef", "--key-id=密钥-名", "--key-version=42",
        "--field=世界", "--field=  首尾空白\t", "--field=",
    ];
    let mixed: &[&str] = &[
        "--key=deadbeef", "--key-id", "密钥-名", "--key-version=42",
        "--field", "世界", "--field=  首尾空白\t", "--field=",
    ];
    let (rec, raw) =
        expect_equivalent_spellings("unicode-whitespace", &[separated, inline, mixed]);
    assert_eq!(
        rec.tag,
        "b5b0f0dbf90d6701f5bc34b74dc407b48a0eab55608c36fb3c1a8016971d42b9"
    );
    assert_eq!(rec.key_id, "密钥-名");
    assert_eq!(rec.key_version, 42);
    assert_eq!(
        rec.fields,
        vec!["世界".to_string(), WS.to_string(), String::new()]
    );

    // No trimming or replacement: the two leading spaces are literal on the
    // wire (the trailing tab is JSON-escaped as \t), and Chinese stays raw
    // UTF-8 in both spellings.
    let text = String::from_utf8(raw).unwrap();
    assert!(text.contains("\"  首尾空白\\t\""), "surrounding whitespace must be preserved: {text}");
    assert!(text.contains("密钥-名"));
    assert!(text.contains("世界"));
}

#[test]
fn key_version_spelling_is_equivalent_and_record_shows_canonical_integer() {
    // Decimal spellings of the same integer authenticate alike, and the record
    // carries the integer: "007" separated equals "7" inline, both version 7.
    let leading_zero: &[&str] =
        &["--key", "00ff", "--key-id", "id", "--key-version", "007", "--field", "v"];
    let plain: &[&str] =
        &["--key=00ff", "--key-id=id", "--key-version=7", "--field=v"];
    let (rec, _) = expect_equivalent_spellings("version-007", &[leading_zero, plain]);
    assert_eq!(rec.key_version, 7);
    assert_eq!(rec.fields, vec!["v".to_string()]);
    assert_eq!(
        rec.tag,
        "3025ffe197bf0c0581c0683a58ec375143e90094f8b5ef39ce6f5c9005ed25c8"
    );
}

#[test]
fn inline_empty_field_is_a_field_and_distinct_from_no_field() {
    // "--field=" is an explicit empty value: one empty field, the same message
    // as the separated "--field \"\"", but a different message from omitting
    // --field altogether (zero fields).
    let inline_empty: &[&str] =
        &["--key=00ff", "--key-id=id", "--key-version=1", "--field="];
    let separated_empty: &[&str] = &[
        "--key", "00ff", "--key-id", "id", "--key-version", "1", "--field", "",
    ];
    let (one_empty, _) =
        expect_equivalent_spellings("one-empty-field", &[inline_empty, separated_empty]);
    assert_eq!(one_empty.fields, vec![String::new()]);
    assert_eq!(
        one_empty.tag,
        "1403803e197b14216fd9d51ff583dfb5eaba67aab92e0e96ba5f873bbeeee164"
    );

    let zero = parse_single_record(
        &run_sign_raw(&["--key=00ff", "--key-id=id", "--key-version=1"]).stdout,
    );
    assert_eq!(zero.fields.len(), 0);
    assert_eq!(
        zero.tag,
        "264a531e2944beb41202f1c1249f2bc1b838f176469a68cdffc484f7ee29b3d6"
    );
    assert_ne!(zero.tag, one_empty.tag, "zero fields vs one empty field must differ");

    // Empty fields interspersed with real ones are neither dropped nor merged,
    // and alternating spellings preserve the same order and count.
    let sep: &[&str] = &[
        "--key", "00ff", "--key-id", "id", "--key-version", "1",
        "--field", "a", "--field", "", "--field", "a", "--field", "",
    ];
    let eq: &[&str] = &[
        "--key=00ff", "--key-id=id", "--key-version=1",
        "--field=a", "--field=", "--field=a", "--field=",
    ];
    let mix: &[&str] = &[
        "--key=00ff", "--key-id", "id", "--key-version=1",
        "--field", "a", "--field=", "--field", "a", "--field=",
    ];
    let (rec, _) = expect_equivalent_spellings("interspersed-empty-fields", &[sep, eq, mix]);
    assert_eq!(
        rec.fields,
        vec!["a".to_string(), String::new(), "a".to_string(), String::new()]
    );
    assert_eq!(
        rec.tag,
        "d688cf9ad91acfb72d3dae79c2a8e734df97b93ce04b0ea0c65b28053f6be83f"
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

#[test]
fn duplicate_single_use_options_are_rejected_across_both_spellings() {
    // A single-use option supplied twice with different spellings is still a
    // duplicate: neither the first nor the last value may win. Both orders are
    // covered, for --key, --key-id and --key-version. stderr must name the
    // known option and call it a duplicate (not a bad/missing value).
    let duplicate_cases: &[(&str, &[&str])] = &[
        // --key: separated then inline, and inline then separated
        (
            "--key",
            &["--key", "00ff", "--key=0102", "--key-id", "i", "--key-version", "1"],
        ),
        (
            "--key",
            &["--key=00ff", "--key", "0102", "--key-id", "i", "--key-version", "1"],
        ),
        // --key-id
        (
            "--key-id",
            &["--key", "00ff", "--key-id", "i", "--key-id=j", "--key-version", "1"],
        ),
        (
            "--key-id",
            &["--key", "00ff", "--key-id=i", "--key-id", "j", "--key-version", "1"],
        ),
        // --key-version
        (
            "--key-version",
            &["--key", "00ff", "--key-id", "i", "--key-version", "1", "--key-version=2"],
        ),
        (
            "--key-version",
            &["--key", "00ff", "--key-id", "i", "--key-version=1", "--key-version", "2"],
        ),
    ];
    for (option, args) in duplicate_cases {
        let stderr = expect_usage_error(args);
        assert!(
            stderr.contains(option),
            "stderr must name {option}: {stderr}"
        );
        assert!(
            stderr.contains("exactly once"),
            "stderr must report a duplicate, not pick a value: {stderr}"
        );
        assert!(
            !stderr.contains("requires a value"),
            "a duplicate is not a missing value: {stderr}"
        );
    }

    // --field is the exception: it may repeat even when the spellings differ,
    // and the two values are kept in order (no "exactly once" error).
    let out = run_sign_raw(&[
        "--key=00ff", "--key-id", "id", "--key-version=1",
        "--field", "first", "--field=second",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    let rec = parse_single_record(&out.stdout);
    assert_eq!(rec.fields, vec!["first".to_string(), "second".to_string()]);
}

#[test]
fn explicit_empty_value_is_invalid_not_missing_for_single_use_options() {
    // "--opt=" supplies an explicit (empty) value: that is an invalid VALUE,
    // distinct from the option being present without a value at all. The
    // separated "--opt \"\"" spelling is the same empty value and must fail
    // identically. stderr names the known option and says its value is illegal;
    // it must not say "requires a value".
    let invalid_empty: &[(&str, &[&str])] = &[
        // empty key: inline and separated
        ("--key", &["--key=", "--key-id", "i", "--key-version", "1"]),
        ("--key", &["--key", "", "--key-id", "i", "--key-version", "1"]),
        // empty key id
        ("--key-id", &["--key", "00ff", "--key-id=", "--key-version", "1"]),
        ("--key-id", &["--key", "00ff", "--key-id", "", "--key-version=1"]),
        // empty version
        (
            "--key-version",
            &["--key=00ff", "--key-id=i", "--key-version="],
        ),
    ];
    for (option, args) in invalid_empty {
        let stderr = expect_usage_error(args);
        assert!(
            stderr.contains(option),
            "stderr must name {option}: {stderr}"
        );
        assert!(
            !stderr.contains("requires a value"),
            "an explicit empty value is invalid, not missing: {stderr}"
        );
        assert!(
            !stderr.contains("exactly once"),
            "an empty value is not a duplicate: {stderr}"
        );
    }

    // The empty key/key-id messages specifically explain the illegal value.
    let stderr = expect_usage_error(&["--key=", "--key-id", "i", "--key-version", "1"]);
    assert!(stderr.contains("--key") && stderr.contains("hexadecimal"), "got: {stderr}");
    let stderr = expect_usage_error(&["--key", "00ff", "--key-id=", "--key-version", "1"]);
    assert!(stderr.contains("--key-id") && stderr.contains("empty"), "got: {stderr}");

    // Contrast: an option left without ANY value at the end is a missing
    // value, while the same option with '=' is an empty field and is legal.
    let stderr = expect_usage_error(&["--key=00ff", "--key-id", "i", "--key-version=1", "--field"]);
    assert!(stderr.contains("--field") && stderr.contains("requires a value"), "got: {stderr}");
    let ok = run_sign_raw(&["--key=00ff", "--key-id", "i", "--key-version=1", "--field="]);
    assert_eq!(ok.status.code(), Some(0));
    assert_eq!(parse_single_record(&ok.stdout).fields, vec![String::new()]);
}

#[test]
fn cross_spelling_errors_never_echo_the_key_or_rejected_value() {
    let secret = "deadbeefcafebabedeadbeefcafebabe";

    // A real key present as the first of a cross-spelling duplicate must not
    // leak when the duplicate is rejected.
    let stderr =
        expect_usage_error(&["--key", secret, "--key=0102", "--key-id", "i", "--key-version", "1"]);
    assert!(!stderr.contains(secret), "stderr echoed the key: {stderr}");
    let stderr =
        expect_usage_error(&["--key=", secret, "--key-id", "i", "--key-version", "1"]);
    // Here "--key=" is an empty invalid key and the secret is a later bare
    // argument; neither the empty-value error nor any message may echo it.
    assert!(!stderr.contains(secret), "stderr echoed the key: {stderr}");
    assert!(stderr.contains("--key"), "stderr must name --key: {stderr}");

    // An inline rejected key value must not be quoted back.
    let stderr = expect_usage_error(&["--key=zz", "--key-id", "i", "--key-version=1"]);
    assert!(!stderr.contains("zz"), "stderr echoed the rejected value: {stderr}");
    assert!(stderr.contains("--key"), "stderr must name --key: {stderr}");

    // A rejected inline key-id value must not be quoted back either.
    let stderr = expect_usage_error(&["--key", "00ff", "--key-id=", "--key-version", "1"]);
    assert!(stderr.contains("--key-id"), "stderr must name --key-id: {stderr}");

    // A valid inline key must stay secret when a later cross-spelling error
    // on another option aborts the run.
    let stderr = expect_usage_error(&[
        &format!("--key={secret}"), "--key-id", "i", "--key-id=j", "--key-version", "1",
    ]);
    assert!(!stderr.contains(secret), "stderr echoed the key: {stderr}");
    assert!(stderr.contains("--key-id"), "stderr must name --key-id: {stderr}");
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

// ---------------------------------------------------------------------------
// verify: records hand-authored as if produced by an *external* program that
// only knows the published format 1 contract.
//
// `sign` is never invoked in this section, so a shared bug in this crate's
// sign/verify pair cannot make these tests pass. Every tag is a golden value
// computed independently with Python's hmac/hashlib/struct straight from the
// byte recipe printed in README.md:
//
//   import hmac, hashlib, struct
//   def encode(key_id, version, fields):
//       out = b"authnote-sign-v1"
//       kb = key_id.encode()
//       out += struct.pack(">Q", len(kb)) + kb
//       out += struct.pack(">I", version)
//       out += struct.pack(">Q", len(fields))
//       for f in fields:
//           fb = f.encode()
//           out += struct.pack(">Q", len(fb)) + fb
//       return out
//   hmac.new(bytes.fromhex(key), encode(key_id, version, fields),
//            hashlib.sha256).hexdigest()
//
// The authenticated content exercises what cannot travel through a command
// line: a NUL (U+0000) flanked by text inside a field, plus Chinese, emoji
// (including a UTF-16 surrogate pair spelling) and real newlines.
// ---------------------------------------------------------------------------


/// Independent Python golden tag over:
/// key `cafecafe...cafe`, key_id `密钥\n🙂`, version 42,
/// fields [`前\u{0000}后`, `世界🙂\n第二行`, ``, `世界🙂\n第二行`].
const EXT_KEY: &str = "cafecafecafecafecafecafecafecafe";
const EXT_TAG: &str = "7474105d623bb03a81eb00b34545fcaf7a8c24002c5a6e58ecfdc6172e1d7f9c";

/// Second external producer: key/key-id for the NUL-vs-empty-field goldens.
const EXT2_KEY: &str = "0123456789abcdef";
const EXT2_KID: &str = "外部记录";
/// Golden tag for key_id `外部记录`, version 1, one field containing only NUL.
const EXT2_NUL_TAG: &str = "cc556672a3f98087fd6dac8c8a8121f517101f784cb7d163cbe4aea5dfbfc559";
/// Golden tag for the same record with the field being the empty string.
const EXT2_EMPTY_TAG: &str = "79548ce691de6cf5ceeeae27190de8140604615becfd21022a0d34c365f2a0db";

/// Substitute the golden-tag placeholder in a hand-written external record.
fn with_tag(template: &str, tag: &str) -> String {
    template.replace("@@TAG@@", tag)
}

fn expect_external_valid(record: &[u8], key: &str) {
    let out = run_verify(key, record);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected valid, stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(
        out.stderr.is_empty(),
        "stderr must be empty on success, got {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn expect_external_mismatch(record: &[u8], key: &str) {
    let out = run_verify(key, record);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected mismatch (exit 1), stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"{\"valid\":false}\n");
    assert!(
        out.stderr.is_empty(),
        "stderr must be empty on mismatch, got {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn external_format1_records_with_nul_chinese_emoji_newline_verify() {
    // Three legal JSON spellings of the SAME decoded record, all carrying the
    // one Python golden tag. Re-spelling, member reordering and reformatting
    // must not require regenerating the tag.

    // (1) Pretty-printed, members in reverse order, padded with JSON
    // whitespace; Chinese/emoji written directly, NUL as \u0000, newline as
    // the short \n escape.
    let pretty = with_tag(
        r#"
  {
    "tag" : "@@TAG@@",
    "fields" : [ "前\u0000后" , "世界🙂\n第二行", "", "世界🙂\n第二行" ],
    "key_version" : 42,
    "key_id" : "密钥\n🙂",
    "algorithm" : "HMAC-SHA256",
    "format" : 1
  }
"#,
        EXT_TAG,
    );
    expect_external_valid(pretty.as_bytes(), EXT_KEY);

    // (2) Compact, canonical member order, and pure ASCII on the wire: every
    // non-ASCII scalar is a \u escape, the emoji (U+1F642) is spelled as its
    // legal UTF-16 surrogate pair, and newlines use \u000a instead of the
    // short \n. Inside the raw string every backslash is literal, so this is
    // exactly the byte sequence an ASCII-only external producer emits; after
    // JSON decoding it is identical to (1). Code points: 密 U+5BC6, 钥 U+94A5,
    // 前 U+524D, 后 U+540E, 世 U+4E16, 界 U+754C, 第 U+7B2C, 二 U+4E8C,
    // 行 U+884C, 🙂 = U+D83D U+DE42.
    let fully_escaped = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"\u5bc6\u94a5\u000a\ud83d\ude42","key_version":42,"fields":["\u524d\u0000\u540e","\u4e16\u754c\ud83d\ude42\u000a\u7b2c\u4e8c\u884c","","\u4e16\u754c\ud83d\ude42\u000a\u7b2c\u4e8c\u884c"],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    assert!(
        fully_escaped.is_ascii(),
        "variant (2) must be pure ASCII on the wire"
    );
    expect_external_valid(fully_escaped.as_bytes(), EXT_KEY);

    // (3) Mixed/direct spelling: raw Chinese/emoji UTF-8, short \n for the
    // newline, \u0000 for the NUL. Verification authenticates decoded text,
    // so the conclusion must be byte-for-byte the same.
    let mixed = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"密钥\n🙂","key_version":42,"fields":["前\u0000后","世界🙂\n第二行","","世界🙂\n第二行"],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    expect_external_valid(mixed.as_bytes(), EXT_KEY);

    // The same external record under the wrong key is a plain mismatch: the
    // golden value proves the positive results above are not vacuous.
    expect_external_mismatch(mixed.as_bytes(), "cafecafecafecafecafecafecafecafd");
}

#[test]
fn nul_field_is_neither_empty_nor_truncating_in_external_records() {
    // A field containing a single NUL authenticates differently from an empty
    // field, even though both render as "" in many naive (C-string) toolkits.
    let nul_only = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"外部记录","key_version":1,"fields":["\u0000"],"tag":"@@TAG@@"}"#,
        EXT2_NUL_TAG,
    );
    let empty_only = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"外部记录","key_version":1,"fields":[""],"tag":"@@TAG@@"}"#,
        EXT2_EMPTY_TAG,
    );
    expect_external_valid(nul_only.as_bytes(), EXT2_KEY);
    expect_external_valid(empty_only.as_bytes(), EXT2_KEY);

    // Cross-tagging the two records must fail: NUL is not silently decoded as
    // the empty string.
    let nul_with_empty_tag = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"外部记录","key_version":1,"fields":["\u0000"],"tag":"@@TAG@@"}"#,
        EXT2_EMPTY_TAG,
    );
    expect_external_mismatch(nul_with_empty_tag.as_bytes(), EXT2_KEY);

    // Text on either side of the NUL participates in the authenticated bytes.
    // The main golden tag covers `前\u{0000}后` whole; dropping the text after
    // or before the NUL while keeping the old tag is a mismatch, proving the
    // NUL neither truncates the field nor hides its surrounding content.
    let suffix_dropped = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"密钥\n🙂","key_version":42,"fields":["前\u0000","世界🙂\n第二行","","世界🙂\n第二行"],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    let prefix_dropped = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"密钥\n🙂","key_version":42,"fields":["\u0000后","世界🙂\n第二行","","世界🙂\n第二行"],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    expect_external_mismatch(suffix_dropped.as_bytes(), EXT_KEY);
    expect_external_mismatch(prefix_dropped.as_bytes(), EXT_KEY);
}

#[test]
fn changed_content_invalidates_old_external_tag() {
    // Every variant stays structurally legal JSON and keeps the ORIGINAL
    // golden tag; only the decoded content moves. Each must be exit 1, never
    // exit 2 and never valid.

    // Delete the NUL from `前\u{0000}后` (and nothing else).
    let nul_deleted = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"密钥\n🙂","key_version":42,"fields":["前后","世界🙂\n第二行","","世界🙂\n第二行"],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    expect_external_mismatch(nul_deleted.as_bytes(), EXT_KEY);

    // Replace every real newline with the two literal characters backslash and
    // 'n' (JSON "\\n"): that decodes to different text, not to a newline.
    let literal_backslash_n = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"密钥\\n🙂","key_version":42,"fields":["前\u0000后","世界🙂\\n第二行","","世界🙂\\n第二行"],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    expect_external_mismatch(literal_backslash_n.as_bytes(), EXT_KEY);

    // Merge away the duplicated field: repeats must not be deduplicated.
    let duplicate_collapsed = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"密钥\n🙂","key_version":42,"fields":["前\u0000后","世界🙂\n第二行",""],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    expect_external_mismatch(duplicate_collapsed.as_bytes(), EXT_KEY);

    // Drop the empty field: a different field count, with no join ambiguity.
    let empty_dropped = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"密钥\n🙂","key_version":42,"fields":["前\u0000后","世界🙂\n第二行","世界🙂\n第二行"],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    expect_external_mismatch(empty_dropped.as_bytes(), EXT_KEY);

    // Reorder two fields: field order is authenticated.
    let reordered = with_tag(
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"密钥\n🙂","key_version":42,"fields":["世界🙂\n第二行","前\u0000后","","世界🙂\n第二行"],"tag":"@@TAG@@"}"#,
        EXT_TAG,
    );
    expect_external_mismatch(reordered.as_bytes(), EXT_KEY);
}

#[test]
fn truncated_or_lone_unicode_escapes_are_corrupt_input_exit_2() {
    let tag64 = "0".repeat(64);
    let record = |fields_json: &str| -> String {
        format!(
            r#"{{"format":1,"algorithm":"HMAC-SHA256","key_id":"{EXT2_KID}","key_version":1,{fields_json},"tag":"{tag64}"}}"#
        )
    };

    // Truncated \u in the middle of a string, and cut off exactly at the end
    // of the input (no closing quote either).
    let truncated_mid = record(r#""fields":["\u000"]"#);
    let truncated_at_eof =
        r#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"外部记录","key_version":1,"fields":["\u00"#.to_string();
    // Surrogate forms that never combine into one legal character.
    let lone_high = record(r#""fields":["\ud83d"]"#);
    let low_out_of_range = record(r#""fields":["\ud83dA"]"#);
    let high_then_high = record(r#""fields":["\ud83d\ud83d"]"#);
    let lone_low = record(r#""fields":["\ude42"]"#);
    let bad_hex_digit = record(r#""fields":["\u00g0"]"#);

    for (label, rec) in [
        ("truncated escape", truncated_mid.as_str()),
        ("truncated escape at EOF", truncated_at_eof.as_str()),
        ("lone high surrogate", lone_high.as_str()),
        ("low surrogate out of range", low_out_of_range.as_str()),
        ("high surrogate paired with high", high_then_high.as_str()),
        ("lone low surrogate", lone_low.as_str()),
        ("non-hex digit in escape", bad_hex_digit.as_str()),
    ] {
        let stderr = expect_verify_invalid(rec.as_bytes(), &["--key", EXT2_KEY]);
        // Error text explains the formatting problem but never quotes the key,
        // record content, or the rejected escape's digits/value.
        assert!(!stderr.contains(EXT2_KEY), "{label}: stderr echoed the key: {stderr}");
        assert!(
            !stderr.contains(EXT2_KID),
            "{label}: stderr echoed record content: {stderr}"
        );
        assert!(
            !stderr.as_bytes().contains(&0),
            "{label}: stderr echoed a NUL byte: {stderr:?}"
        );
        assert!(
            !stderr.contains("d83d") && !stderr.contains("de42"),
            "{label}: stderr echoed the rejected escape value: {stderr}"
        );
    }

    // A raw, unescaped NUL byte in the JSON text is corrupt input too: it may
    // not be accepted as the escaped NUL and must not cut the string short.
    let mut raw_nul = record(r#""fields":["前@后"]"#).into_bytes();
    let at_pos = raw_nul.iter().position(|&b| b == b'@').unwrap();
    raw_nul[at_pos] = 0;
    let stderr = expect_verify_invalid(&raw_nul, &["--key", EXT2_KEY]);
    assert!(!stderr.contains(EXT2_KEY), "stderr echoed the key: {stderr}");
    assert!(!stderr.as_bytes().contains(&0), "stderr echoed the NUL: {stderr:?}");
}

// ---------------------------------------------------------------------------
// verify: member names are recognized by their JSON-decoded text
//
// An external program that saves or re-formats a record may spell a member
// name with \u escapes; the name is recognized by its decoded text, so the
// rewrite stays valid. The same decoding rule makes two spellings of one
// decoded name a duplicate member (exit 2), and never promotes a look-alike
// name (different case, surrounding whitespace, extra characters) into a
// known member.
// ---------------------------------------------------------------------------

/// Overwrite the spelling of one member name inside a compact signed record.
/// `spelling` is the raw JSON text of the replacement name (without the
/// quotes), so escape sequences can be supplied exactly as they appear on
/// the wire.
fn respell_member(record: &str, canonical: &str, spelling: &str) -> String {
    let needle = format!("\"{canonical}\":");
    assert_eq!(
        record.matches(&needle).count(),
        1,
        "record must contain member {canonical} exactly once: {record}"
    );
    record.replacen(&needle, &format!("\"{spelling}\":"), 1)
}

#[test]
fn verify_member_names_may_be_spelled_with_unicode_escapes() {
    let key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    // Repeated field text on purpose: duplicate array items are content, not
    // duplicate members, and must keep verifying after the rewrite.
    let record = sign_record_bytes(key, "demo", "3", &["hello", "世界", "世界"]);
    let body = String::from_utf8(record)
        .unwrap()
        .trim_end_matches('\n')
        .to_string();

    // Each of key_id, fields and tag, one at a time, spelled with an
    // equivalent \u escape: the decoded name is unchanged, so the record
    // still verifies.
    for (canonical, spelling) in [
        ("key_id", "key_\\u0069d"),
        ("fields", "\\u0066ields"),
        ("tag", "ta\\u0067"),
    ] {
        let rewritten = respell_member(&body, canonical, spelling);
        let out = run_verify(key, rewritten.as_bytes());
        assert_eq!(
            out.status.code(),
            Some(0),
            "respelled {canonical}: stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":true}\n");
        assert!(out.stderr.is_empty());
    }

    // All three rewrites at once, members reordered, escaped and direct
    // spellings mixed: still the same decoded record.
    let tag = Json::parse(&body).get("tag").as_str().to_string();
    let reordered = format!(
        "{{\"ta\\u0067\":\"{tag}\",\"\\u0066ields\":[\"hello\",\"世界\",\"世界\"],\"key_version\":3,\"key_\\u0069d\":\"demo\",\"algorithm\":\"HMAC-SHA256\",\"format\":1}}"
    );
    let out = run_verify(key, reordered.as_bytes());
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(out.stderr.is_empty());
}

#[test]
fn verify_respelled_member_names_with_wrong_key_is_a_plain_mismatch() {
    let key = "00ff";
    let record = sign_record_bytes(key, "id", "1", &["x"]);
    let body = String::from_utf8(record)
        .unwrap()
        .trim_end_matches('\n')
        .to_string();
    // The legal rewrite does not change the authenticated content, so a
    // wrong key is still an ordinary mismatch, never a structural error.
    let rewritten = respell_member(&body, "key_id", "key_\\u0069d");
    let out = run_verify("ff00", rewritten.as_bytes());
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"{\"valid\":false}\n");
    assert!(out.stderr.is_empty());
}

#[test]
fn verify_member_names_that_decode_to_a_duplicate_are_rejected() {
    let key = "00ff";
    let record = sign_record_bytes(key, "kid-secret-name", "1", &["fieldtext"]);
    let body = String::from_utf8(record)
        .unwrap()
        .trim_end_matches('\n')
        .to_string();
    let tag = Json::parse(&body).get("tag").as_str().to_string();
    let zeros = "0".repeat(64);

    // Each case carries two members whose names decode to the same text.
    // Covered: value-equal and value-differing pairs, both orders, two
    // different escape spellings of one name, and a tag pair where one copy
    // holds the CORRECT tag. Neither the first nor the last value may be
    // picked: every variant is structurally corrupt and must exit 2.
    let duplicates: Vec<String> = vec![
        // key_id: literal then escaped, same value
        body.replacen(
            "\"key_id\":\"kid-secret-name\"",
            "\"key_id\":\"kid-secret-name\",\"key_\\u0069d\":\"kid-secret-name\"",
            1,
        ),
        // escaped then literal, same value
        body.replacen(
            "\"key_id\":\"kid-secret-name\"",
            "\"key_\\u0069d\":\"kid-secret-name\",\"key_id\":\"kid-secret-name\"",
            1,
        ),
        // different values, both orders
        body.replacen(
            "\"key_id\":\"kid-secret-name\"",
            "\"key_id\":\"kid-secret-name\",\"key_\\u0069d\":\"other\"",
            1,
        ),
        body.replacen(
            "\"key_id\":\"kid-secret-name\"",
            "\"key_\\u0069d\":\"other\",\"key_id\":\"kid-secret-name\"",
            1,
        ),
        // two different escape spellings of the same decoded name
        body.replacen(
            "\"key_id\":\"kid-secret-name\"",
            "\"key_\\u0069d\":\"kid-secret-name\",\"key_\\u0069\\u0064\":\"kid-secret-name\"",
            1,
        ),
        // fields: same value, and escaped-first with a different value
        body.replacen(
            "\"fields\":[\"fieldtext\"]",
            "\"fields\":[\"fieldtext\"],\"fie\\u006cds\":[\"fieldtext\"]",
            1,
        ),
        body.replacen(
            "\"fields\":[\"fieldtext\"]",
            "\"fie\\u006cds\":[],\"fields\":[\"fieldtext\"]",
            1,
        ),
        // tag: both copies carry the CORRECT tag; still a duplicate
        body.replacen(
            &format!("\"tag\":\"{tag}\""),
            &format!("\"tag\":\"{tag}\",\"ta\\u0067\":\"{tag}\""),
            1,
        ),
        body.replacen(
            &format!("\"tag\":\"{tag}\""),
            &format!("\"ta\\u0067\":\"{tag}\",\"tag\":\"{tag}\""),
            1,
        ),
        // tag: second copy different
        body.replacen(
            &format!("\"tag\":\"{tag}\""),
            &format!("\"tag\":\"{tag}\",\"ta\\u0067\":\"{zeros}\""),
            1,
        ),
    ];

    for rec in &duplicates {
        let out = run_verify(key, rec.as_bytes());
        assert_eq!(out.status.code(), Some(2), "expected exit 2 for {rec}");
        assert!(out.stdout.is_empty(), "stdout must be empty on exit 2");
        let stderr = String::from_utf8(out.stderr).expect("stderr must be UTF-8");
        assert!(
            stderr.to_lowercase().contains("duplicate"),
            "stderr must call out the duplicate member: {stderr}"
        );
        // The error must not echo the key, the record content, the rejected
        // member spelling, or the tag.
        assert!(!stderr.contains(key), "stderr echoed the key: {stderr}");
        assert!(
            !stderr.contains("kid-secret-name"),
            "stderr echoed record content: {stderr}"
        );
        assert!(
            !stderr.contains("fieldtext"),
            "stderr echoed a field: {stderr}"
        );
        assert!(!stderr.contains(&tag), "stderr echoed the tag: {stderr}");
        assert!(
            !stderr.contains("0069") && !stderr.contains("0064") && !stderr.contains("0067"),
            "stderr echoed the escaped member spelling: {stderr}"
        );
    }
}

#[test]
fn verify_lookalike_member_names_are_never_recognized() {
    let key = "00ff";
    let record = sign_record_bytes(key, "kid-secret-name", "1", &["fieldtext"]);
    let body = String::from_utf8(record)
        .unwrap()
        .trim_end_matches('\n')
        .to_string();

    // Names whose decoded text is not exactly a known member: escapes do not
    // make extra members legal, and case or surrounding whitespace is never
    // auto-corrected. Each record is otherwise complete and legal, so the
    // unknown member is the only problem. The second element of each pair
    // lists spellings of the rejected name that stderr must not echo.
    let cases: Vec<(String, Vec<&str>)> = vec![
        // different case
        (body.replacen("\"key_id\"", "\"Key_id\"", 1), vec!["Key_id"]),
        // leading / trailing whitespace
        (body.replacen("\"key_id\"", "\" key_id\"", 1), vec![" key_id"]),
        (body.replacen("\"key_id\"", "\"key_id \"", 1), vec!["key_id "]),
        // extra character
        (body.replacen("\"key_id\"", "\"key_ids\"", 1), vec!["key_ids"]),
        // escape spellings that decode to non-members
        (
            body.replacen("\"key_id\"", "\"key_\\u0069ds\"", 1),
            vec!["key_ids", "0069"],
        ),
        (
            body.replacen("\"fields\"", "\"FIELD\\u0053\"", 1),
            vec!["FIELDS", "0053"],
        ),
        (
            body.replacen("\"tag\"", "\"ta\\u0067x\"", 1),
            vec!["tagx", "0067"],
        ),
        // an outright extra member alongside all six legal ones
        (
            body.replacen("{\"format\"", "{\"keyidx\":1,\"format\"", 1),
            vec!["keyidx"],
        ),
    ];

    for (rec, rejected_spellings) in &cases {
        let stderr = expect_verify_invalid(rec.as_bytes(), &["--key", key]);
        assert!(
            stderr.contains("unexpected member"),
            "stderr must describe the structural problem: {stderr}"
        );
        assert!(!stderr.contains(key), "stderr echoed the key: {stderr}");
        assert!(
            !stderr.contains("kid-secret-name"),
            "stderr echoed record content: {stderr}"
        );
        assert!(
            !stderr.contains("fieldtext"),
            "stderr echoed a field: {stderr}"
        );
        for spelling in rejected_spellings {
            assert!(
                !stderr.contains(spelling),
                "stderr echoed the rejected member name {spelling:?}: {stderr}"
            );
        }
    }
}
