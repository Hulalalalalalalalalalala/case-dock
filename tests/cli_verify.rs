//! End-to-end tests for the observable result of `authnote verify`.
//!
//! Valid records are produced by the real `sign` binary (so these tests cover
//! the documented "sign ... | verify ..." flow with no conversion), while
//! malformed and mutated records are hand-built byte strings so that every
//! rejection path can be exercised precisely. Assertions pin the exact
//! stdout/stderr/exit-code contract:
//!   valid match           -> exit 0, stdout `{"valid":true}`,  empty stderr
//!   valid record mismatch -> exit 1, stdout `{"valid":false}`, empty stderr
//!   unusable input        -> exit 2, empty stdout,             stderr explains

use std::process::{Command, Output};

fn authnote() -> Command {
    Command::new(env!("CARGO_BIN_EXE_authnote"))
}

/// Run `verify --key <key>` feeding `stdin` verbatim.
fn run_verify(key: &str, stdin: &[u8]) -> Output {
    run_verify_args(&["--key", key], stdin)
}

/// Run `verify` with a raw argument vector (for argument-error cases).
fn run_verify_args(args: &[&str], stdin: &[u8]) -> Output {
    let mut cmd = authnote();
    cmd.arg("verify");
    for a in args {
        cmd.arg(a);
    }
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    use std::io::Write;
    let mut child = cmd.spawn().expect("failed to execute authnote");
    // A record whose arguments are rejected (exit 2) legitimately exits before
    // reading stdin, in which case the kernel may report EPIPE on our write;
    // that is expected, not a harness failure. Any other write error is real.
    if let Err(e) = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin)
    {
        assert!(
            e.kind() == std::io::ErrorKind::BrokenPipe,
            "failed to write stdin: {e}"
        );
    }
    child
        .wait_with_output()
        .expect("failed to await authnote")
}

/// Run `sign` and return its single stdout line (without the trailing newline).
fn sign_record(key: &str, key_id: &str, version: &str, fields: &[&str]) -> String {
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
    let out = cmd.output().expect("failed to execute authnote sign");
    assert_eq!(out.status.code(), Some(0), "sign setup failed");
    let text = String::from_utf8(out.stdout).expect("sign stdout is UTF-8");
    text.strip_suffix('\n')
        .expect("sign stdout ends with newline")
        .to_string()
}

/// Minimal JSON string escaper for hand-built records.
fn json_quote(s: &str) -> String {
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

/// Build a canonical format-1 record from raw pieces. `tag` is inserted
/// verbatim (already JSON-escaped content is not needed: tags are hex).
fn record(key_id: &str, version: &str, fields: &[&str], tag: &str) -> String {
    let fields = fields
        .iter()
        .map(|f| json_quote(f))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":{},\"key_version\":{},\"fields\":[{}],\"tag\":\"{}\"}}",
        json_quote(key_id),
        version,
        fields,
        tag,
    )
}

const KEY: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
const DEMO_TAG: &str = "e451500f028e969efb0d6fe533ab40a90d2e8267112cd5c95804d86f7f076d8f";

// ---------------------------------------------------------------------------
// Outcome assertions.
// ---------------------------------------------------------------------------

fn expect_valid(out: &Output, label: &str) {
    assert_eq!(out.status.code(), Some(0), "{label}: expected exit 0");
    assert_eq!(
        out.stdout,
        b"{\"valid\":true}\n",
        "{label}: exact stdout mismatch, got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.stderr.is_empty(),
        "{label}: stderr must be empty, got {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn expect_invalid(out: &Output, label: &str) {
    assert_eq!(out.status.code(), Some(1), "{label}: expected exit 1");
    assert_eq!(
        out.stdout,
        b"{\"valid\":false}\n",
        "{label}: exact stdout mismatch, got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.stderr.is_empty(),
        "{label}: stderr must be empty, got {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn expect_error(out: &Output, label: &str) -> String {
    assert_eq!(out.status.code(), Some(2), "{label}: expected exit 2");
    assert!(
        out.stdout.is_empty(),
        "{label}: stdout must be empty, got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8(out.stderr.clone())
        .unwrap_or_else(|_| panic!("{label}: stderr must be valid UTF-8"));
    assert!(!stderr.trim().is_empty(), "{label}: stderr must explain");
    stderr
}

// ---------------------------------------------------------------------------
// Success / mismatch paths.
// ---------------------------------------------------------------------------

#[test]
fn verifies_the_readme_record_and_real_sign_pipeline() {
    // The exact golden record from README.md verifies as-is.
    let rec = record("demo", "3", &["hello", "世界"], DEMO_TAG);
    expect_valid(&run_verify(KEY, rec.as_bytes()), "readme");

    // sign ... | verify ... round trip, with the verify key in another case.
    let signed = sign_record("deadbeef", "密钥", "42", &["a\nb", "", "世界🙂"]);
    expect_valid(
        &run_verify("DEADBEEF", signed.as_bytes()),
        "pipeline-uppercase-key",
    );

    // --key=HEX inline form works too.
    expect_valid(
        &run_verify_args(&[&format!("--key={KEY}")], rec.as_bytes()),
        "inline-key",
    );
}

#[test]
fn wrong_key_reports_mismatch_not_error() {
    let rec = record("demo", "3", &["hello", "世界"], DEMO_TAG);
    expect_invalid(
        &run_verify("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c", rec.as_bytes()),
        "wrong-key",
    );
}

#[test]
fn any_authenticated_change_reports_mismatch() {
    let valid = record("demo", "3", &["hello", "世界"], DEMO_TAG);
    let cases: &[(&str, String)] = &[
        ("field-content", record("demo", "3", &["hello", "世界!"], DEMO_TAG)),
        ("field-order", record("demo", "3", &["世界", "hello"], DEMO_TAG)),
        ("extra-field", record("demo", "3", &["hello", "世界", ""], DEMO_TAG)),
        ("missing-field", record("demo", "3", &["hello"], DEMO_TAG)),
        ("key-id", record("demo2", "3", &["hello", "世界"], DEMO_TAG)),
        ("version", record("demo", "4", &["hello", "世界"], DEMO_TAG)),
        ("tag-flipped", {
            let mut t = DEMO_TAG.to_string();
            t.replace_range(0..1, if &t[0..1] == "0" { "1" } else { "0" });
            record("demo", "3", &["hello", "世界"], &t)
        }),
        ("empty-vs-zero-fields", record("demo", "3", &[], DEMO_TAG)),
    ];
    for (label, bad) in cases {
        assert_ne!(bad, &valid, "{label}: case must actually differ");
        expect_invalid(&run_verify(KEY, bad.as_bytes()), label);
    }
}

#[test]
fn zero_fields_and_one_empty_field_are_both_verifiable_and_distinct() {
    let empty = sign_record("00ff", "id", "1", &[]);
    let one_empty = sign_record("00ff", "id", "1", &[""]);
    expect_valid(&run_verify("00ff", empty.as_bytes()), "zero-fields");
    expect_valid(
        &run_verify("00ff", one_empty.as_bytes()),
        "one-empty-field",
    );
    // Swapping tags between the two records must fail: they are different
    // messages even though neither contains visible text.
    let empty_tag = &empty[empty.rfind("\"tag\":\"").unwrap() + 7..empty.len() - 2];
    let one_tag =
        &one_empty[one_empty.rfind("\"tag\":\"").unwrap() + 7..one_empty.len() - 2];
    expect_invalid(
        &run_verify("00ff", record("id", "1", &[], one_tag).as_bytes()),
        "zero-fields-wrong-tag",
    );
    expect_invalid(
        &run_verify("00ff", record("id", "1", &[""], empty_tag).as_bytes()),
        "empty-field-wrong-tag",
    );
}

#[test]
fn duplicate_and_reordered_fields_authenticate_as_decoded() {
    let dup = sign_record("0102", "id", "1", &["x", "x"]);
    expect_valid(&run_verify("0102", dup.as_bytes()), "dup");
    // Same tag attached to a single-field record must not verify.
    let dup_tag = &dup[dup.rfind("\"tag\":\"").unwrap() + 7..dup.len() - 2];
    expect_invalid(
        &run_verify("0102", record("id", "1", &["x"], dup_tag).as_bytes()),
        "single-with-dup-tag",
    );

    let ab = sign_record("0102", "id", "1", &["a", "b"]);
    expect_valid(&run_verify("0102", ab.as_bytes()), "ab");
    let ab_tag = &ab[ab.rfind("\"tag\":\"").unwrap() + 7..ab.len() - 2];
    expect_invalid(
        &run_verify("0102", record("id", "1", &["b", "a"], ab_tag).as_bytes()),
        "swapped-fields",
    );
}

#[test]
fn reformatting_member_order_and_tag_case_do_not_affect_verification() {
    let pretty = format!(
        "  \n\t{{\n  \"tag\": \"{}\",\n  \"fields\": [\n    \"hello\",\n    \"世界\"\n  ],\n  \"key_version\": 3,\n  \"key_id\": \"demo\",\n  \"algorithm\": \"HMAC-SHA256\",\n  \"format\": 1\n}}\r\n  ",
        DEMO_TAG.to_uppercase(),
    );
    expect_valid(&run_verify(KEY, pretty.as_bytes()), "pretty-reordered");

    // Same six members in every shuffled order verify identically.
    let members = [
        "\"format\":1",
        "\"algorithm\":\"HMAC-SHA256\"",
        "\"key_id\":\"demo\"",
        "\"key_version\":3",
        "\"fields\":[\"hello\",\"世界\"]",
        &format!("\"tag\":\"{DEMO_TAG}\""),
    ];
    let mut shuffled = members.to_vec();
    shuffled.rotate_left(2);
    let doc = format!("{{{}}} ", shuffled.join(","));
    expect_valid(&run_verify(KEY, doc.as_bytes()), "shuffled-order");

    // JSON whitespace inside strings is content, not padding: escaping a tab
    // inside a field keeps the same decoded text.
    let signed = sign_record("00ff", "id", "1", &["a\tb"]);
    let spaced = signed.replace("[\"a\\tb\"]", "[ \"a\\tb\" ]");
    expect_valid(
        &run_verify("00ff", spaced.as_bytes()),
        "array-inner-whitespace",
    );
}

#[test]
fn unicode_escapes_and_raw_multibyte_text_verify_identically() {
    // Record produced by sign with raw multibyte content verifies directly.
    let signed = sign_record("00ff", "kid-名", "7", &["中文🙂\n\"\\"]);
    expect_valid(&run_verify("00ff", signed.as_bytes()), "raw-unicode");

    // The same logical text, written with pure-ASCII \uXXXX / surrogate-pair
    // escapes, with sign's real tag carried over: JSON decoding must produce
    // the identical authenticated text.
    let real_tag = {
        let start = signed.rfind("\"tag\":\"").unwrap() + 7;
        signed[start..signed.len() - 2].to_string()
    };
    let escaped = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"kid-\\u540d\",\"key_version\":7,\"fields\":[\"\\u4e2d\\u6587\\ud83d\\ude42\\n\\\"\\\\\"],\"tag\":\"{real_tag}\"}}"
    );
    expect_valid(&run_verify("00ff", escaped.as_bytes()), "escaped-unicode");

    // An escape encoding with the wrong text (dropping one CJK character) must
    // not verify even though every byte is well-formed JSON.
    let tampered = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"kid-\\u540d\",\"key_version\":7,\"fields\":[\"\\u4e2d\\ud83d\\ude42\\n\\\"\\\\\"],\"tag\":\"{real_tag}\"}}"
    );
    expect_invalid(&run_verify("00ff", tampered.as_bytes()), "escaped-tampered");
}

// ---------------------------------------------------------------------------
// Exactly-one-record enforcement.
// ---------------------------------------------------------------------------

#[test]
fn only_one_complete_record_is_accepted() {
    let rec = record("demo", "3", &["hello", "世界"], DEMO_TAG);

    // Leading/trailing JSON whitespace (all four RFC 8259 spaces) is fine.
    expect_valid(
        &run_verify(KEY, format!(" \t\r\n{rec}\n\r\t ").as_bytes()),
        "surrounding-ws",
    );

    // Multiple objects, even with whitespace between them, are rejected.
    expect_error(
        &run_verify(KEY, format!("{rec}{rec}").as_bytes()),
        "two-objects-no-gap",
    );
    expect_error(
        &run_verify(KEY, format!("{rec}\n{rec}").as_bytes()),
        "two-objects-newline",
    );

    // Trailing non-whitespace content of any shape is rejected.
    for suffix in ["x", "0", "true", "null", "\"s\"", "[]", "{}", ","] {
        expect_error(
            &run_verify(KEY, format!("{rec}{suffix}").as_bytes()),
            &format!("trailing-{suffix}"),
        );
    }

    // Empty and whitespace-only inputs are rejected, never verified.
    expect_error(&run_verify(KEY, b""), "empty");
    expect_error(&run_verify(KEY, b"   \n\t\r"), "whitespace-only");

    // A UTF-8 BOM is not JSON whitespace.
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(rec.as_bytes());
    expect_error(&run_verify(KEY, &bom), "leading-bom");

    // Non-UTF-8 bytes anywhere in the input.
    let mut bad = rec.as_bytes().to_vec();
    bad.push(0xFF);
    expect_error(&run_verify(KEY, &bad), "trailing-non-utf8");
    expect_error(&run_verify(KEY, &[0xFF, 0xFE]), "non-utf8");
}

// ---------------------------------------------------------------------------
// Malformed JSON / record structure.
// ---------------------------------------------------------------------------

#[test]
fn broken_json_is_rejected_with_exit_2() {
    let cases: &[(&str, &[u8])] = &[
        ("not-json", b"not json".as_slice()),
        ("unterminated-object", b"{".as_slice()),
        ("unterminated-string", b"{\"a\": \"x".as_slice()),
        ("bad-escape", br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"a\q","key_version":1,"fields":[],"tag":"0000000000000000000000000000000000000000000000000000000000000000"}"#),
        // Raw tab byte (Rust `\t`) inside a JSON string is unescaped control.
        ("control-in-string", b"{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"a\tb\",\"key_version\":1,\"fields\":[],\"tag\":\"0000000000000000000000000000000000000000000000000000000000000000\"}".as_slice()),
        ("unpaired-high-surrogate", "{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"\\uD800\",\"key_version\":1,\"fields\":[],\"tag\":\"0000000000000000000000000000000000000000000000000000000000000000\"}".as_bytes()),
        ("leading-zero-number", br#"{"format":01,"algorithm":"HMAC-SHA256","key_id":"a","key_version":1,"fields":[],"tag":"0000000000000000000000000000000000000000000000000000000000000000"}"#),
        ("missing-colon", br#"{"format" 1,"algorithm":"HMAC-SHA256","key_id":"a","key_version":1,"fields":[],"tag":"0000000000000000000000000000000000000000000000000000000000000000"}"#),
        ("trailing-comma", br#"{"format":1,"algorithm":"HMAC-SHA256","key_id":"a","key_version":1,"fields":[],"tag":"0000000000000000000000000000000000000000000000000000000000000000",}"#),
    ];
    for (label, input) in cases {
        expect_error(&run_verify(KEY, input), label);
    }
}

fn zero_tag() -> String {
    "0".repeat(64)
}

#[test]
fn duplicate_and_unknown_members_are_rejected() {
    let dup_format = format!(
        "{{\"format\":1,\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"a\",\"key_version\":1,\"fields\":[],\"tag\":\"{}\"}}",
        zero_tag()
    );
    expect_error(&run_verify(KEY, dup_format.as_bytes()), "dup-format");
    let dup_tag_field = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"a\",\"key_version\":1,\"fields\":[],\"fields\":[],\"tag\":\"{}\"}}",
        zero_tag()
    );
    expect_error(
        &run_verify(KEY, dup_tag_field.as_bytes()),
        "dup-fields",
    );
    let unknown = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"a\",\"key_version\":1,\"fields\":[],\"tag\":\"{}\",\"extra\":1}}",
        zero_tag()
    );
    expect_error(&run_verify(KEY, unknown.as_bytes()), "unknown-member");
}

#[test]
fn missing_required_members_are_rejected() {
    let full = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"a\",\"key_version\":1,\"fields\":[],\"tag\":\"{}\"}}",
        zero_tag()
    );
    let remove = |needle: &str| -> String {
        let mut s = full.clone();
        let start = s.find(needle).unwrap();
        let mut end = start + needle.len();
        // swallow the following comma too, keeping the JSON parseable
        if end < s.len() && s.as_bytes()[end] == b',' {
            end += 1;
        } else if start > 0 && s.as_bytes()[start - 1] == b',' {
            s.replace_range(start - 1..end, "");
            return s;
        }
        s.replace_range(start..end, "");
        s
    };
    for member in [
        "\"format\":1",
        "\"algorithm\":\"HMAC-SHA256\"",
        "\"key_id\":\"a\"",
        "\"key_version\":1",
        "\"fields\":[]",
        &format!("\"tag\":\"{}\"", zero_tag()),
    ] {
        let doc = remove(member);
        expect_error(&run_verify(KEY, doc.as_bytes()), &format!("missing-{member}"));
    }
    expect_error(&run_verify(KEY, b"{}"), "empty-object");
}

#[test]
fn wrong_member_types_and_values_are_rejected() {
    let t = zero_tag();
    let good = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"a\",\"key_version\":1,\"fields\":[],\"tag\":\"{t}\"}}"
    );
    let replace = |needle: &str, replacement: &str| {
        good.replacen(needle, replacement, 1)
    };

    let bad: &[(&str, String)] = &[
        // format
        ("format-string", replace("\"format\":1", "\"format\":\"1\"")),
        ("format-float", replace("\"format\":1", "\"format\":1.0")),
        ("format-bool", replace("\"format\":1", "\"format\":true")),
        ("format-null", replace("\"format\":1", "\"format\":null")),
        ("format-array", replace("\"format\":1", "\"format\":[1]")),
        ("format-negative", replace("\"format\":1", "\"format\":-1")),
        // algorithm
        ("algo-number", replace("\"algorithm\":\"HMAC-SHA256\"", "\"algorithm\":1")),
        ("algo-null", replace("\"algorithm\":\"HMAC-SHA256\"", "\"algorithm\":null")),
        // key_id
        ("keyid-number", replace("\"key_id\":\"a\"", "\"key_id\":1")),
        ("keyid-empty", replace("\"key_id\":\"a\"", "\"key_id\":\"\"")),
        ("keyid-array", replace("\"key_id\":\"a\"", "\"key_id\":[]")),
        // key_version
        ("version-zero", replace("\"key_version\":1", "\"key_version\":0")),
        ("version-negative", replace("\"key_version\":1", "\"key_version\":-1")),
        ("version-overflow", replace("\"key_version\":1", "\"key_version\":4294967296")),
        ("version-float", replace("\"key_version\":1", "\"key_version\":1.0")),
        ("version-exponent", replace("\"key_version\":1", "\"key_version\":1e0")),
        ("version-string", replace("\"key_version\":1", "\"key_version\":\"1\"")),
        ("version-bool", replace("\"key_version\":1", "\"key_version\":true")),
        ("version-null", replace("\"key_version\":1", "\"key_version\":null")),
        ("version-huge", replace("\"key_version\":1", "\"key_version\":999999999999999999999999")),
        // fields
        ("fields-string", replace("\"fields\":[]", "\"fields\":\"x\"")),
        ("fields-number", replace("\"fields\":[]", "\"fields\":1")),
        ("fields-object", replace("\"fields\":[]", "\"fields\":{}")),
        ("fields-null", replace("\"fields\":[]", "\"fields\":null")),
        ("field-number", replace("\"fields\":[]", "\"fields\":[1]")),
        ("field-bool", replace("\"fields\":[]", "\"fields\":[true]")),
        ("field-null", replace("\"fields\":[]", "\"fields\":[null]")),
        ("field-object", replace("\"fields\":[]", "\"fields\":[{}]")),
        ("field-nested-array", replace("\"fields\":[]", "\"fields\":[[\"x\"]]")),
        // tag
        ("tag-63-hex", replace(&format!("\"tag\":\"{t}\""), &format!("\"tag\":\"{}\"", &t[1..]))),
        ("tag-65-hex", replace(&format!("\"tag\":\"{t}\""), &format!("\"tag\":\"{}0\"", t))),
        ("tag-non-hex", replace(&format!("\"tag\":\"{t}\""), &format!("\"tag\":\"{}\"", "z".repeat(64)))),
        ("tag-odd-short", replace(&format!("\"tag\":\"{t}\""), "\"tag\":\"abc\"")),
        ("tag-number", replace(&format!("\"tag\":\"{t}\""), "\"tag\":1")),
        ("tag-array", replace(&format!("\"tag\":\"{t}\""), "\"tag\":[]")),
        ("tag-empty", replace(&format!("\"tag\":\"{t}\""), "\"tag\":\"\"")),
    ];
    for (label, doc) in bad {
        expect_error(&run_verify(KEY, doc.as_bytes()), label);
    }
}

#[test]
fn top_level_must_be_a_single_object() {
    expect_error(&run_verify(KEY, b"[]"), "array");
    expect_error(&run_verify(KEY, b"\"x\""), "string");
    expect_error(&run_verify(KEY, b"1"), "number");
    expect_error(&run_verify(KEY, b"true"), "bool");
    expect_error(&run_verify(KEY, b"null"), "null");
}

#[test]
fn unsupported_versions_and_algorithms_are_rejected_explicitly() {
    let t = zero_tag();
    for version in ["0", "2", "99", "18446744073709551616"] {
        let doc = format!(
            "{{\"format\":{version},\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"a\",\"key_version\":1,\"fields\":[],\"tag\":\"{t}\"}}"
        );
        let stderr = expect_error(&run_verify(KEY, doc.as_bytes()), &format!("format-{version}"));
        assert!(
            stderr.to_lowercase().contains("unsupported"),
            "format {version} must be reported unsupported, got: {stderr}"
        );
    }

    for algo in ["HMAC-SHA512", "hmac-sha256", "", "HMAC-SHA256 ", "SHA-256"] {
        let doc = format!(
            "{{\"format\":1,\"algorithm\":\"{algo}\",\"key_id\":\"a\",\"key_version\":1,\"fields\":[],\"tag\":\"{t}\"}}"
        );
        let stderr = expect_error(&run_verify(KEY, doc.as_bytes()), &format!("algo-{algo}"));
        assert!(
            stderr.to_lowercase().contains("unsupported"),
            "algorithm {algo:?} must be reported unsupported, got: {stderr}"
        );
    }

    // Crucially, an unsupported version/algorithm must never authenticate
    // using current rules: even with a valid format-1 tag present, exit is 2
    // and stdout is empty.
    let doc = format!(
        "{{\"format\":2,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"demo\",\"key_version\":3,\"fields\":[\"hello\"],\"tag\":\"{DEMO_TAG}\"}}"
    );
    let out = run_verify(KEY, doc.as_bytes());
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

#[test]
fn tag_may_use_uppercase_hex_when_it_represents_32_bytes() {
    let rec = record("demo", "3", &["hello", "世界"], &DEMO_TAG.to_uppercase());
    expect_valid(&run_verify(KEY, rec.as_bytes()), "uppercase-tag");

    // Mixed case also decodes to the same 32 bytes.
    let mixed: String = DEMO_TAG
        .chars()
        .enumerate()
        .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c })
        .collect();
    let rec = record("demo", "3", &["hello", "世界"], &mixed);
    expect_valid(&run_verify(KEY, rec.as_bytes()), "mixedcase-tag");
}

// ---------------------------------------------------------------------------
// verify command-line argument handling (same contract as sign).
// ---------------------------------------------------------------------------

#[test]
fn verify_key_argument_errors_match_sign_conventions() {
    let rec = record("demo", "3", &["hello", "世界"], DEMO_TAG);
    let input = rec.as_bytes();

    expect_error(&run_verify_args(&[], input), "no-args");
    expect_error(&run_verify_args(&["--key"], input), "missing-value");
    expect_error(
        &run_verify_args(&["--key", ""], input),
        "empty-key",
    );
    expect_error(
        &run_verify_args(&["--key", "abc"], input),
        "odd-length-key",
    );
    expect_error(
        &run_verify_args(&["--key", "zz"], input),
        "non-hex-key",
    );
    expect_error(
        &run_verify_args(&["--key", "00ff", "--key", "00ff"], input),
        "duplicate-key",
    );
    expect_error(
        &run_verify_args(&["--bogus", "00ff"], input),
        "unknown-option",
    );
    expect_error(
        &run_verify_args(&["00ff"], input),
        "positional",
    );
    expect_error(
        &run_verify_args(&["--key=abc"], input),
        "inline-bad-key",
    );
}

#[test]
fn verify_errors_never_echo_the_key_or_record_values() {
    let secret = "deadbeefcafebabedeadbeefcafebabe";

    // Rejected --key value.
    let stderr = expect_error(
        &run_verify_args(&["--key", "abczzz"], b"{}"),
        "bad-key-arg",
    );
    assert!(!stderr.contains("abczzz"));

    // A valid secret key must not leak when record parsing fails.
    let stderr = expect_error(
        &run_verify_args(&["--key", secret], b"not json at all"),
        "broken-record",
    );
    assert!(!stderr.contains(secret), "leaked key: {stderr}");

    // Same when an argument later turns out invalid.
    let stderr = expect_error(
        &run_verify_args(&["--key", secret, "--bogus"], b"{}"),
        "bad-arg",
    );
    assert!(!stderr.contains(secret), "leaked key: {stderr}");

    // Structurally rejected records must not be quoted back either.
    let loud_id = "do-not-echo-this-identifier-9f8e";
    let doc = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"{loud_id}\",\"key_id\":\"{loud_id}\",\"key_version\":1,\"fields\":[],\"tag\":\"{}\"}}",
        "0".repeat(64)
    );
    let stderr = expect_error(&run_verify("00ff", doc.as_bytes()), "dup-member");
    assert!(
        !stderr.contains(loud_id),
        "stderr must not quote record values: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Compatibility: existing public behavior is unchanged.
// ---------------------------------------------------------------------------

#[test]
fn sign_and_version_still_behave_as_before() {
    let out = authnote().arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"authnote 0.1.0\n");
    assert!(out.stderr.is_empty());

    let out = authnote().output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("verify"));
}

#[test]
fn existing_format1_records_verify_without_conversion() {
    // A record typed byte-for-byte as `sign` would have emitted it, but
    // obtained independently here (hand-written canonical JSON, golden tag
    // from the README).
    let raw = "{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"demo\",\"key_version\":3,\"fields\":[\"hello\",\"世界\"],\"tag\":\"e451500f028e969efb0d6fe533ab40a90d2e8267112cd5c95804d86f7f076d8f\"}";
    expect_valid(&run_verify(KEY, raw.as_bytes()), "canonical");
}
