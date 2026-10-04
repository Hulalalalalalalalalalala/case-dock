//! End-to-end regression coverage for the `sign` command line.
//!
//! These tests run the built `authnote` binary and assert on its observable
//! contract: exit status, the single JSON record on stdout, and stderr.
//!
//! Expected tags are NOT recomputed with the crate under test: they are fixed
//! values derived independently from the format-1 byte layout published in
//! README.md, using standard HMAC-SHA256 (cross-checked with Python's hmac
//! module). They therefore catch a change in the encoding and the printed
//! record at the same time.

use std::io::Write;
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------------
// Minimal JSON value parser (no third-party crates are available offline).
// It parses just what an authnote record contains: objects, arrays, strings
// (with full escape/\uXXXX handling), unsigned integers, booleans, null.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Json {
    Num(u64),
    Str(String),
    Array(Vec<Json>),
    // Kept as an ordered list of (key, value) pairs.
    Object(Vec<(String, Json)>),
}

impl Json {
    fn parse(input: &str) -> Json {
        let mut p = Parser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        p.skip_ws();
        let v = p.value();
        p.skip_ws();
        assert!(p.pos == p.bytes.len(), "trailing data after JSON value");
        v
    }

    fn as_str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("expected JSON string, got {other:?}"),
        }
    }

    fn as_u64(&self) -> u64 {
        match self {
            Json::Num(n) => *n,
            other => panic!("expected JSON number, got {other:?}"),
        }
    }

    fn as_array(&self) -> &[Json] {
        match self {
            Json::Array(a) => a,
            other => panic!("expected JSON array, got {other:?}"),
        }
    }

    fn field<'a>(&'a self, key: &str) -> &'a Json {
        match self {
            Json::Object(entries) => entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing field {key:?} in {self:?}")),
            other => panic!("expected JSON object, got {other:?}"),
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> u8 {
        self.bytes[self.pos]
    }

    fn eat(&mut self, b: u8) {
        assert!(self.pos < self.bytes.len() && self.bytes[self.pos] == b,
            "expected {:?} at byte {}", b as char, self.pos);
        self.pos += 1;
    }

    fn value(&mut self) -> Json {
        self.skip_ws();
        match self.peek() {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Json::Str(self.string()),
            b'0'..=b'9' => self.number(),
            other => panic!("unexpected byte {other:?} at {}", self.pos),
        }
    }

    fn number(&mut self) -> Json {
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
        Json::Num(text.parse().unwrap())
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = String::new();
        loop {
            let b = self.peek();
            self.pos += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let e = self.peek();
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4();
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // High surrogate; require a following low surrogate.
                                assert!(self.peek() == b'\\');
                                self.pos += 1;
                                assert!(self.peek() == b'u');
                                self.pos += 1;
                                let lo = self.hex4();
                                assert!((0xDC00..=0xDFFF).contains(&lo), "bad low surrogate");
                                let c = 0x10000
                                    + ((cp - 0xD800) << 10)
                                    + (lo - 0xDC00);
                                out.push(char::from_u32(c).unwrap());
                            } else {
                                out.push(char::from_u32(cp).unwrap());
                            }
                        }
                        other => panic!("bad escape \\{}", other as char),
                    }
                }
                _ => {
                    // Copy one raw UTF-8 byte at a time; validating at push time
                    // is awkward, so accumulate the byte run and convert below.
                    let run_start = self.pos - 1;
                    while self.pos < self.bytes.len()
                        && !matches!(self.bytes[self.pos], b'"' | b'\\')
                    {
                        // Control characters must be escaped in JSON.
                        assert!(self.bytes[self.pos] >= 0x20,
                            "unescaped control byte at {}", self.pos);
                        self.pos += 1;
                    }
                    out.push_str(
                        std::str::from_utf8(&self.bytes[run_start..self.pos]).unwrap(),
                    );
                }
            }
        }
        out
    }

    fn hex4(&mut self) -> u32 {
        let s = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4]).unwrap();
        self.pos += 4;
        u32::from_str_radix(s, 16).unwrap()
    }

    fn array(&mut self) -> Json {
        self.eat(b'[');
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == b']' {
            self.pos += 1;
            return Json::Array(items);
        }
        loop {
            items.push(self.value());
            self.skip_ws();
            match self.peek() {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    break;
                }
                other => panic!("expected , or ] in array, got {other:?}"),
            }
        }
        Json::Array(items)
    }

    fn object(&mut self) -> Json {
        self.eat(b'{');
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == b'}' {
            self.pos += 1;
            return Json::Object(entries);
        }
        loop {
            self.skip_ws();
            let key = self.string();
            self.skip_ws();
            self.eat(b':');
            let value = self.value();
            entries.push((key, value));
            self.skip_ws();
            match self.peek() {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    break;
                }
                other => panic!("expected , or }} in object, got {other:?}"),
            }
        }
        Json::Object(entries)
    }
}

// ---------------------------------------------------------------------------
// Running the binary
// ---------------------------------------------------------------------------

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_sign(args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_authnote");
    let output = Command::new(bin)
        .arg("sign")
        .args(args)
        .output()
        .expect("failed to run authnote");
    Output {
        code: output.status.code().expect("terminated by signal"),
        stdout: String::from_utf8(output.stdout).expect("stdout is not UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr is not UTF-8"),
    }
}

fn sign_args(key: &str, key_id: &str, version: u32, fields: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--key".into(),
        key.into(),
        "--key-id".into(),
        key_id.into(),
        "--key-version".into(),
        version.to_string(),
    ];
    for f in fields {
        args.push("--field".into());
        args.push((*f).into());
    }
    args
}

fn sign_record(key: &str, key_id: &str, version: u32, fields: &[&str]) -> Json {
    let args = sign_args(key, key_id, version, fields);
    let out = run_sign(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_success(&out);
    // Exactly one record: a single line terminated by one '\n', nothing else.
    assert!(
        out.stdout.ends_with('\n'),
        "stdout must end with a newline: {:?}",
        out.stdout
    );
    assert_eq!(
        out.stdout.matches('\n').count(),
        1,
        "stdout must contain exactly one JSON line: {:?}",
        out.stdout
    );
    let line = out.stdout.trim_end_matches('\n');
    Json::parse(line)
}

fn assert_success(out: &Output) {
    assert_eq!(out.code, 0, "unexpected failure: {:?}", out.stderr);
    assert_eq!(out.stderr, "", "stderr must be empty on success");
    assert!(!out.stdout.is_empty(), "stdout must contain a record");
}

/// Assert the shared record envelope and return `(fields, tag)`.
fn assert_envelope(record: &Json, expected_key_id: &str, expected_version: u64) -> (Vec<String>, String) {
    assert_eq!(record.field("format").as_u64(), 1, "format must be 1");
    assert_eq!(record.field("algorithm").as_str(), "HMAC-SHA256");
    assert_eq!(record.field("key_id").as_str(), expected_key_id);
    assert_eq!(record.field("key_version").as_u64(), expected_version);
    // The record must contain no other keys than the documented set.
    let expected_keys =
        ["format", "algorithm", "key_id", "key_version", "fields", "tag"];
    if let Json::Object(entries) = record {
        assert_eq!(entries.len(), expected_keys.len(), "unexpected record keys");
        for (k, _) in entries {
            assert!(
                expected_keys.contains(&k.as_str()),
                "undocumented key {k}"
            );
        }
    } else {
        panic!("record must be a JSON object");
    }
    let fields: Vec<String> = record
        .field("fields")
        .as_array()
        .iter()
        .map(|v| v.as_str().to_string())
        .collect();
    let tag = record.field("tag").as_str().to_string();
    assert_eq!(tag.len(), 64, "tag must be 64 hex characters: {tag}");
    assert!(
        tag.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "tag must be lowercase hexadecimal: {tag}"
    );
    (fields, tag)
}

fn expect_record(key: &str, key_id: &str, version: u32, fields: &[&str], expected_tag: &str) {
    let record = sign_record(key, key_id, version, fields);
    let (got_fields, got_tag) = assert_envelope(&record, key_id, version as u64);
    assert_eq!(got_fields, fields, "recorded fields must match input");
    assert_eq!(got_tag, expected_tag, "tag mismatch for fields {fields:?}");
}

// ---------------------------------------------------------------------------
// Success: full record shape
// ---------------------------------------------------------------------------

#[test]
fn readme_example_record_is_stable() {
    // The exact record shown in README.md; tag derived from the published
    // format-1 layout with standard HMAC-SHA256.
    expect_record(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "demo",
        3,
        &["hello", "世界"],
        "e451500f028e969efb0d6fe533ab40a90d2e8267112cd5c95804d86f7f076d8f",
    );
}

#[test]
fn stdout_is_exactly_one_record_and_stderr_empty() {
    let out = run_sign(&[
        "--key", "aabb",
        "--key-id", "k",
        "--key-version", "1",
        "--field", "x",
    ]);
    assert_success(&out);
    assert_eq!(out.stdout.matches('\n').count(), 1);
    assert_eq!(&out.stdout[..1], "{");
    assert_eq!(&out.stdout[out.stdout.len() - 2..], "}\n");
    let record = Json::parse(out.stdout.trim_end_matches('\n'));
    assert_envelope(&record, "k", 1);
}

#[test]
fn key_is_never_part_of_the_record() {
    // A distinctive 16-byte key that must never appear in the wire output
    // (a short key could occur inside the hex tag by chance; 32 hex chars
    // cannot). Checked against the raw stdout bytes, not the parsed record.
    let key = "deadbeefcafebabe0102030405060708";
    let args = sign_args(key, "kid", 42, &["anything"]);
    let out = run_sign(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_success(&out);
    assert!(!out.stdout.contains(key));
    assert!(!out.stdout.contains(&key.to_uppercase()));
}

// ---------------------------------------------------------------------------
// Success: JSON escaping must preserve the authenticated text character-wise
// ---------------------------------------------------------------------------

#[test]
fn json_escaping_round_trips_utf8_and_controls() {
    // Every category of text that needs JSON escaping, plus multibyte UTF-8.
    // (The NUL byte is deliberately excluded: it cannot cross an argv
    // boundary on Unix; u0001/u001f stand in for the <0x20 control path.)
    let fields = [
        "中文 漢字",
        "😀 🚫",
        "double \"quotes\"",
        "back\\slash",
        "line1\nline2",
        "cr\rreturn",
        "tab\there",
        "bs\u{0008}ff\u{000c}end",
        "ctrl\u{0001}\u{001f}",
        "",
    ];
    let args = sign_args("0123456789abcdef", "kid-名前", 7, &fields);
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let out = run_sign(&arg_refs);
    assert_success(&out);
    let record = Json::parse(out.stdout.trim_end_matches('\n'));
    let (got_fields, tag) = assert_envelope(&record, "kid-名前", 7);

    // Parsing the printed record must recover the input character for
    // character; escaping exists only on the wire, not in the authenticated
    // text.
    assert_eq!(got_fields.len(), fields.len());
    for (expected, got) in fields.iter().zip(&got_fields) {
        assert_eq!(expected, got, "escaping changed the field text");
    }

    // Raw control bytes are forbidden unescaped in JSON strings, while the
    // multibyte UTF-8 text is emitted as itself rather than \u-escaped.
    let stdout = &out.stdout;
    assert!(stdout.contains("中文"));
    assert!(stdout.contains("😀"));
    assert!(stdout.contains("\\\""));
    assert!(stdout.contains("\\\\"));
    assert!(stdout.contains("\\n"));
    assert!(stdout.contains("\\r"));
    assert!(stdout.contains("\\t"));
    assert!(stdout.contains("\\u0008"));
    assert!(stdout.contains("\\u000c"));
    assert!(stdout.contains("\\u0001"));
    assert!(stdout.contains("\\u001f"));
    assert!(!stdout.contains('\u{0001}'));
    assert!(!stdout.contains('\u{001f}'));

    // Independently computed tag for the raw (unescaped) fields: proves the
    // MAC was computed over the original text rather than over the JSON wire
    // form.
    assert_eq!(
        tag,
        "eeb89a052ff7504d16aee28678cd82233b14cc9e43ed4403d2e103645ecac16b"
    );
}

// ---------------------------------------------------------------------------
// Tag values: fixed expectations from the published byte-level contract
// ---------------------------------------------------------------------------

#[test]
fn empty_message_differs_from_one_empty_field() {
    // Zero fields: legal input, empty message.
    expect_record(
        "aabbccdd",
        "k",
        1,
        &[],
        "d05349077d11b3db17797b67eb54163ce2f8201c333117769bdb6159557f233a",
    );
    // Exactly one empty field: same key/text bytes, distinct authenticated
    // content and a distinct, independently computed tag.
    expect_record(
        "aabbccdd",
        "k",
        1,
        &[""],
        "1f98ec7fedcdf31b862e6bb261257c76bad8c71df2ad699aa3728da047f1df32",
    );
}

#[test]
fn duplicate_fields_are_retained_and_bound() {
    // ["x","x"] is neither ["x"] nor the 2-character text "xx".
    expect_record(
        "aabbccdd",
        "k",
        1,
        &["x", "x"],
        "50416a9e490a1bbc3af22050b41fe97ffc655cfc2258e5b072a0ed62ca924ade",
    );
    expect_record(
        "aabbccdd",
        "k",
        1,
        &["x"],
        "09445b6294944e8abdb544cd63af47ded32bdb2e5840562018a407f5661e550d",
    );
    // Single field "xx": independently recomputed. Must differ from the
    // duplicated-field record, otherwise the encoding collapsed fields into
    // simple text concatenation.
    expect_record(
        "aabbccdd",
        "k",
        1,
        &["xx"],
        "3183c729dc9fb25266b7664b79b2ac8e902496960f749e2ee736b3dd32f3cb62",
    );
}

#[test]
fn concatenated_text_is_not_the_same_as_two_fields() {
    // Independent reference tags for the split and joined forms; they must
    // not be equal to each other.
    let split = sign_record("aabbccdd", "k", 1, &["ab", "c"]);
    let joined = sign_record("aabbccdd", "k", 1, &["abc"]);
    let (split_fields, split_tag) = assert_envelope(&split, "k", 1);
    let (joined_fields, joined_tag) = assert_envelope(&joined, "k", 1);
    assert_eq!(split_fields, ["ab", "c"]);
    assert_eq!(joined_fields, ["abc"]);
    assert_ne!(
        split_tag, joined_tag,
        "length-prefixed boundaries must distinguish [\"ab\",\"c\"] from [\"abc\"]"
    );
    // Fixed values for both:
    assert_eq!(
        split_tag,
        "cab163f0afe7cda8320ee9f8e7d339a93e027406cefa3c0e07b3db934dc9a68e"
    );
    assert_eq!(
        joined_tag,
        "7c32714646a044ce59cd2d0808b5d7d38eb4a1cdfabaa9d140d03afcd7a895e8"
    );

    // The two adjacent-split variants share characters but encode differently.
    expect_record(
        "00ff",
        "id",
        1,
        &["a", "bc"],
        "79184921ce69b3b60b371655d9da69baea3199fb09d30c4652f8caf6c2d17028",
    );
}

#[test]
fn field_order_is_authenticated() {
    expect_record(
        "00ff",
        "id",
        1,
        &["a", "b"],
        "a71b82e6f52f60d7cf05256cab2bc15742ff4b8f4f64fcea5e18033a0dbc370f",
    );
    // Swapping the fields must not yield the original record's tag, and the
    // fields in the record must be swapped too.
    let swapped = sign_record("00ff", "id", 1, &["b", "a"]);
    let (swapped_fields, swapped_tag) = assert_envelope(&swapped, "id", 1);
    assert_eq!(swapped_fields, ["b", "a"]);
    assert_eq!(
        swapped_tag,
        "5f17e9f39f6912f56d94b8aeaac6fc1ecea2794e132894ef1360601af6032662"
    );
    assert_ne!(
        swapped_tag,
        "a71b82e6f52f60d7cf05256cab2bc15742ff4b8f4f64fcea5e18033a0dbc370f"
    );
}

#[test]
fn utf8_byte_length_not_char_count_is_used() {
    // "世界" is 2 characters but 6 UTF-8 bytes. If the length prefix held a
    // character count instead, the encoded bytes and therefore the tag would
    // differ from this independently computed reference value.
    expect_record(
        "00ff",
        "id",
        1,
        &["世界"],
        "6a71a15e6157bfe2c98277314178c7fb04070d8ac9482dff66fd4ea4084858fd",
    );
    // "é" (U+00E9): 1 char, 2 bytes.
    expect_record(
        "00ff",
        "id",
        1,
        &["é"],
        "0a0d1264786153d4cee915619413d30a55e0886069d13a4aaccb0290bd20b8de",
    );
}

#[test]
fn same_inputs_give_same_tag_and_hex_case_is_ignored() {
    let lower = sign_record("00ff", "id", 1, &["x"]);
    let upper = sign_record("00FF", "id", 1, &["x"]);
    let (_, tag_lower) = assert_envelope(&lower, "id", 1);
    let (_, tag_upper) = assert_envelope(&upper, "id", 1);
    assert_eq!(tag_lower, tag_upper, "hex letter case must not matter");
    assert_eq!(
        tag_lower,
        "2ebc5f9c2a6edd8a4b103dd6262003e5a521f3984ee1d202a63216ef10d0bf32"
    );

    // Repeated invocations with identical arguments are byte-stable.
    let again = sign_record("00ff", "id", 1, &["x"]);
    assert_eq!(format!("{lower:?}"), format!("{again:?}"));
}

#[test]
fn changing_key_id_version_or_fields_changes_the_tag() {
    let base = sign_record("00ff", "id", 1, &["x"]);
    let (_, base_tag) = assert_envelope(&base, "id", 1);

    let other_id = sign_record("00ff", "id2", 1, &["x"]);
    let (fields_id, tag_id) = assert_envelope(&other_id, "id2", 1);
    assert_eq!(fields_id, ["x"]);
    assert_ne!(tag_id, base_tag);
    assert_eq!(
        tag_id,
        "0ce18fc4c634e836848081defe3270a74e4357912baab995c1568090d0c081b7"
    );

    let other_ver = sign_record("00ff", "id", 2, &["x"]);
    let (_, tag_ver) = assert_envelope(&other_ver, "id", 2);
    assert_ne!(tag_ver, base_tag);
    assert_eq!(
        tag_ver,
        "5bb5cfb53a0ba13aa4d014918ea99b838e0846272a5737fbfef73397737254e5"
    );

    let other_field = sign_record("00ff", "id", 1, &["y"]);
    let (fields_y, tag_y) = assert_envelope(&other_field, "id", 1);
    assert_eq!(fields_y, ["y"]);
    assert_ne!(tag_y, base_tag);
    assert_eq!(
        tag_y,
        "1e9e2db986d7bfbc1cca11718387a4a2938286f872dddc61ca2660b29fc8b166"
    );

    // A different actual key changes the tag without altering the record text.
    let other_key = sign_record("ff00", "id", 1, &["x"]);
    let (fields_k, tag_k) = assert_envelope(&other_key, "id", 1);
    assert_eq!(fields_k, ["x"]);
    assert_ne!(tag_k, base_tag);
    assert_eq!(
        tag_k,
        "9757269a5b500da6ad908822ac00a4204c87f5e504b92fb58d92094c30314dc6"
    );
}

#[test]
fn fields_and_tag_change_together() {
    // For each modified record both the printed fields array AND the tag must
    // track the modification: a test that only compared an intermediate MAC
    // could miss a record/encoding drift.
    let base = sign_record("00ff", "id", 1, &["ab", "c"]);
    let (base_fields, base_tag) = assert_envelope(&base, "id", 1);

    let changed = sign_record("00ff", "id", 1, &["ab", "d"]);
    let (changed_fields, changed_tag) = assert_envelope(&changed, "id", 1);
    assert_ne!(base_fields, changed_fields);
    assert_ne!(base_tag, changed_tag);

    let removed = sign_record("00ff", "id", 1, &["ab"]);
    let (removed_fields, removed_tag) = assert_envelope(&removed, "id", 1);
    assert_ne!(base_fields, removed_fields);
    assert_ne!(base_tag, removed_tag);
}

#[test]
fn equals_form_and_utf8_key_id_are_supported() {
    // --opt=value form and a non-ASCII key id must produce the same record.
    let spaced = sign_args("aabbccdd", "标识", 9, &["v", "w"]);
    let out = Command::new(env!("CARGO_BIN_EXE_authnote"))
        .arg("sign")
        .arg("--key=aabbccdd")
        .arg("--key-id=标识")
        .arg("--key-version=9")
        .arg("--field=v")
        .arg("--field=w")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    let inline = Json::parse(std::str::from_utf8(&out.stdout).unwrap().trim_end_matches('\n'));
    let spaced_out = run_sign(&spaced.iter().map(String::as_str).collect::<Vec<_>>());
    let spaced_rec = Json::parse(spaced_out.stdout.trim_end_matches('\n'));
    assert_eq!(format!("{inline:?}"), format!("{spaced_rec:?}"));
}

// ---------------------------------------------------------------------------
// Failures: exit code 2, empty stdout, explanatory stderr, key never echoed
// ---------------------------------------------------------------------------

fn expect_failure(args: &[&str], secret: &str) -> String {
    let out = run_sign(args);
    assert_eq!(
        out.code, 2,
        "expected exit code 2 for {args:?}, got {} / {:?}",
        out.code, out.stdout
    );
    assert_eq!(out.stdout, "", "stdout must be empty on failure");
    assert!(!out.stderr.is_empty(), "stderr must explain the failure");
    assert_eq!(out.stderr.matches('\n').count(), 1, "one error line");
    // `contains("")` is always true, so the echo check only makes sense for a
    // non-empty secret.
    if !secret.is_empty() {
        assert!(
            !out.stderr.contains(secret),
            "stderr must not echo the key: {}",
            out.stderr
        );
        assert!(
            !out.stderr.contains(&secret.to_uppercase()),
            "stderr must not echo the key in upper case: {}",
            out.stderr
        );
    }
    out.stderr
}

#[test]
fn invalid_keys_fail_without_echoing() {
    let secret = "ab12deadbeef";

    // Odd-length hex.
    let err = expect_failure(
        &["--key", "abc", "--key-id", "k", "--key-version", "1"],
        "abc",
    );
    assert!(err.to_lowercase().contains("hex") || err.contains("--key"));

    // Non-hex characters.
    expect_failure(
        &["--key", "zz", "--key-id", "k", "--key-version", "1"],
        "zz",
    );

    // Empty key (option given an empty value).
    expect_failure(
        &["--key", "", "--key-id", "k", "--key-version", "1"],
        "",
    );

    // A valid key combined with an out-of-range version: the key stays hidden.
    let err = expect_failure(
        &["--key", secret, "--key-id", "k", "--key-version", "0"],
        secret,
    );
    assert!(err.contains("version") || err.contains("--key-version"));
    expect_failure(
        &["--key", secret, "--key-id", "k", "--key-version", "4294967296"],
        secret,
    );
    expect_failure(
        &["--key", secret, "--key-id", "k", "--key-version", "1.5"],
        secret,
    );
}

#[test]
fn missing_required_options_fail() {
    expect_failure(&[], "");
    expect_failure(&["--key-id", "k", "--key-version", "1"], "");
    expect_failure(
        &["--key", "aabb", "--key-version", "1"],
        "aabb",
    );
    expect_failure(&["--key", "aabb", "--key-id", "k"], "aabb");
}

#[test]
fn other_cli_errors_fail_without_echoing_key() {
    let secret = "01020304";

    // Option missing its value.
    expect_failure(
        &["--key", secret, "--key-id", "k", "--key-version"],
        secret,
    );

    // Unknown option: the key seen before the error must not be echoed.
    expect_failure(
        &["--key", secret, "--key-id", "k", "--key-version", "1", "--bogus", "x"],
        secret,
    );

    // Duplicate required option.
    expect_failure(
        &[
            "--key", secret, "--key", "05060708",
            "--key-id", "k", "--key-version", "1",
        ],
        secret,
    );

    // Unknown option appearing before the key: still exit 2 and empty stdout.
    let out = run_sign(&["--nope", "x"]);
    assert_eq!(out.code, 2);
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}

#[test]
fn malformed_key_is_not_written_anywhere() {
    // Even an invalid key string must never be reflected back.
    let secret = "c0ffee-c0ffee"; // contains a non-hex byte and is odd length
    let out = run_sign(&[
        "--key", secret,
        "--key-id", "k",
        "--key-version", "1",
    ]);
    assert_eq!(out.code, 2);
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.contains(secret));
}

#[test]
fn stdin_is_not_consumed_and_output_is_a_single_process_contract() {
    // Feeding unexpected bytes on stdin must not change anything: sign takes
    // no input from stdin and still emits exactly one record.
    let bin = env!("CARGO_BIN_EXE_authnote");
    let mut child = Command::new(bin)
        .arg("sign")
        .arg("--key")
        .arg("aabb")
        .arg("--key-id")
        .arg("k")
        .arg("--key-version")
        .arg("1")
        .arg("--field")
        .arg("data on stdin is ignored")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"garbage that must be ignored\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches('\n').count(), 1);
    let record = Json::parse(stdout.trim_end_matches('\n'));
    assert_envelope(&record, "k", 1);
}
