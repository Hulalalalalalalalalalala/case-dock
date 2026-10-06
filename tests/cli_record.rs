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

// ---------------------------------------------------------------------------
// verify: key_version regression coverage
//
// The key version participates in the authenticated content AND is constrained
// by the record grammar, so callers must be able to tell apart:
//   * a structurally legal record whose tag does not match (exit 1), and
//   * a record whose key_version spelling or range is illegal (exit 2).
// Every tag below is an independent Python golden over the format-1 contract
// in README.md (key 00ff, key_id "kidprobe", one field "verprobe"); `sign` is
// not used to produce the boundary/mismatch records, so a shared sign/verify
// bug cannot make these pass.
// ---------------------------------------------------------------------------

const KV_KEY: &str = "00ff";
/// A different but well-formed key: choosing the wrong key must turn a
/// structurally legal record into a mismatch, never into corrupt input.
const KV_WRONG_KEY: &str = "0102";
const KV_KID: &str = "kidprobe";
const KV_FIELD: &str = "verprobe";
/// Golden tag at version 1 (the range's low endpoint).
const KV_TAG_V1: &str = "4301ff56f516eef690d78758c6fd0311d90391920d1b4a5eddd0cdc2966e4a53";
/// Golden tag at version 4294967295 (the range's high endpoint, u32::MAX).
const KV_TAG_VMAX: &str = "5760ad7d9bfc942d2754bce443165a5db296460b9401a4dea878137d9b960e64";
/// Golden tag at version 7 (what `sign --key-version 007` must authenticate).
const KV_TAG_V7: &str = "deabcb0017a1462e2d59490a499830033877d4b13450f8a502e5cea18e4dc798";

/// Hand-author a record with an arbitrary *raw* `key_version` token (which may
/// be illegal JSON) and an arbitrary tag.
fn kv_record(version_token: &str, tag: &str) -> String {
    format!(
        r#"{{"format":1,"algorithm":"HMAC-SHA256","key_id":"{KV_KID}","key_version":{version_token},"fields":["{KV_FIELD}"],"tag":"{tag}"}}"#
    )
}

#[test]
fn verify_key_version_range_endpoints_are_normal_versions() {
    // Both endpoints of 1..=4294967295 are ordinary usable versions: with the
    // correct key the record verifies (exit 0, exactly one {"valid":true}
    // line, empty stderr). The key version is independent of the record's
    // format version: a key version other than 1 must never be reported as an
    // unsupported format.
    for (token, golden) in [("1", KV_TAG_V1), ("4294967295", KV_TAG_VMAX)] {
        let rec = kv_record(token, golden);

        let out = run_verify(KV_KEY, rec.as_bytes());
        assert_eq!(out.status.code(), Some(0), "version {token}: stderr={:?}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.stdout, b"{\"valid\":true}\n");
        assert!(out.stderr.is_empty(), "version {token}: stderr must be empty");

        // The same structurally legal record under a wrong key is a mismatch,
        // not a format/structure rejection.
        let out = run_verify(KV_WRONG_KEY, rec.as_bytes());
        assert_eq!(out.status.code(), Some(1), "version {token}: wrong key must mismatch");
        assert_eq!(out.stdout, b"{\"valid\":false}\n");
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn verify_changing_an_in_range_key_version_is_a_mismatch_not_corruption() {
    // Everything else (including the original tag) stays fixed; only the
    // version moves to another in-range integer. The record stays legal but
    // the authenticated content changed, so the result is exit 1 with BOTH the
    // correct key and a wrong key: a wrong key must not reclassify the legal
    // version number as corrupt input.
    let variants = [
        kv_record("2", KV_TAG_V1),                 // 1 -> 2
        kv_record("4294967295", KV_TAG_V1),        // 1 -> high endpoint
        kv_record("1", KV_TAG_VMAX),               // max -> 1 with max's tag
        // Legal JSON whitespace around members and around the number must not
        // change the version's meaning: still a structural legal mismatch.
        format!(
            r#"{{ "format" : 1 , "algorithm" : "HMAC-SHA256" , "key_id" : "{KV_KID}" , "key_version" : 2 , "fields" : [ "{KV_FIELD}" ] , "tag" : "{KV_TAG_V1}" }}"#
        ),
    ];
    for rec in variants {
        for key in [KV_KEY, KV_WRONG_KEY] {
            let out = run_verify(key, rec.as_bytes());
            assert_eq!(
                out.status.code(),
                Some(1),
                "expected mismatch for {rec}, stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(out.stdout, b"{\"valid\":false}\n");
            assert!(out.stderr.is_empty(), "mismatch must be silent on stderr");
        }
    }
}

#[test]
fn verify_illegal_key_version_spellings_are_corrupt_input() {
    // None of these may be accepted as integer 7 (or any other integer):
    // quoted text, fraction, exponent, leading zero are not JSON integers;
    // zero/negative/above-max are out of range; the huge decimal is far beyond
    // integer parse range and must not truncate, round or wrap to a valid
    // version. Every one is exit 2: empty stdout and a stderr that explains
    // the number/version problem without echoing the key, record text or the
    // rejected literal. The outcome is identical when a valid-but-wrong key is
    // supplied: structural invalidity takes precedence over authentication.
    let cases: &[&str] = &[
        r#""7""#,                                  // string, not a number
        "7.0",                                     // fraction spelling of 7
        "7e0",                                     // exponent spelling of 7
        "007",                                     // leading zero
        "0",                                       // below range
        "-0",                                      // parses numerically to 0: still below range
        "-1",                                      // negative
        "4294967296",                              // one above the max
        "99999999999999999999999999999999999999999", // far beyond i128 parsing
    ];
    for token in cases {
        for key in [KV_KEY, KV_WRONG_KEY] {
            let out = run_verify(key, kv_record(token, KV_TAG_V1).as_bytes());
            assert_eq!(
                out.status.code(),
                Some(2),
                "token {token:?}: expected corrupt input (exit 2), key={key}"
            );
            assert!(out.stdout.is_empty(), "token {token:?}: stdout must be empty");
            let stderr = String::from_utf8(out.stderr).expect("stderr must be UTF-8");
            assert!(
                !stderr.trim().is_empty(),
                "token {token:?}: stderr must explain the problem"
            );
            let lower = stderr.to_lowercase();
            assert!(
                lower.contains("number") || lower.contains("integer") || lower.contains("version"),
                "token {token:?}: stderr must describe the number/version problem: {stderr}"
            );
            // Never echo the key, any record text, or the full record.
            assert!(!stderr.contains(key), "token {token:?}: stderr echoed the key: {stderr}");
            assert!(!stderr.contains(KV_KID), "token {token:?}: stderr echoed key id: {stderr}");
            assert!(!stderr.contains(KV_FIELD), "token {token:?}: stderr echoed a field: {stderr}");
            assert!(!stderr.contains(KV_TAG_V1), "token {token:?}: stderr echoed the tag/record: {stderr}");

            // The same record padded with legal JSON whitespace stays corrupt:
            // whitespace cannot launder a bad number spelling.
            let padded = format!(" \n\t{}\r\n  ", kv_record(token, KV_TAG_V1));
            let out = run_verify(key, padded.as_bytes());
            assert_eq!(
                out.status.code(),
                Some(2),
                "token {token:?}: padding must not make it accepted, key={key}"
            );
            assert!(out.stdout.is_empty());
        }
    }

    // The rejected literal itself must not be quoted back (checked for the
    // distinctive spellings whose digits do not legitimately appear in the
    // fixed "1..=4294967295" range text).
    for token in &[r#""7""#, "7.0", "7e0", "007", "4294967296",
                   "99999999999999999999999999999999999999999"] {
        for key in [KV_KEY, KV_WRONG_KEY] {
            let out = run_verify(key, kv_record(token, KV_TAG_V1).as_bytes());
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !stderr.contains(token),
                "token {token:?}: stderr echoed the rejected literal: {stderr}"
            );
        }
    }
}

#[test]
fn sign_key_version_007_canonicalizes_but_record_007_is_corrupt() {
    // The command line and the record grammar differ on purpose: sign's
    // --key-version is decimal command-line text, so "007" means integer 7;
    // the emitted record must carry the canonical integer spelling 7 and then
    // verify normally.
    let out = run_sign(KV_KEY, KV_KID, "007", &[KV_FIELD]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    let signed = String::from_utf8(out.stdout).unwrap();
    assert!(signed.contains("\"key_version\":7"), "record must carry integer 7: {signed}");
    assert!(!signed.contains("\"key_version\":007"), "record must not carry 007: {signed}");
    let rec = parse_single_record(signed.as_bytes());
    assert_eq!(rec.key_version, 7);
    assert_eq!(rec.tag, KV_TAG_V7, "007 must authenticate as integer 7");

    // The produced record verifies as-is, and again when surrounded only by
    // legal JSON whitespace.
    let body = signed.trim_end_matches('\n');
    for input in [signed.as_bytes().to_vec(), format!(" \t\n{body}  \r\n").into_bytes()] {
        let out = run_verify(KV_KEY, &input);
        assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.stdout, b"{\"valid\":true}\n");
        assert!(out.stderr.is_empty());
    }

    // Rewriting the number INSIDE the record to 007 crosses the grammar line:
    // leading zeros are corrupt JSON, exit 2 (not a mismatch and not integer 7).
    let tampered = body.replace("\"key_version\":7", "\"key_version\":007");
    assert_ne!(tampered, body);
    let out = run_verify(KV_KEY, tampered.as_bytes());
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(KV_KEY), "stderr echoed the key: {stderr}");
    assert!(!stderr.contains(KV_FIELD), "stderr echoed a field: {stderr}");
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

// ---------------------------------------------------------------------------
// Long keys: at and beyond the 64-byte SHA-256 HMAC block.
//
// A user-supplied key is any non-empty, even-length hex string; keys whose
// decoded length exceeds one SHA-256 block (64 bytes) must NOT be rejected or
// truncated — standard HMAC hashes such keys first (RFC 2104 / RFC 4231).
// Every golden tag below was computed independently with Python's
// hmac/hashlib/struct straight from the format-1 byte contract in README.md
// (and cross-checked with openssl), never derived from this crate's own HMAC
// code, so a shared sign/verify bug cannot make these tests pass.
//
// All cases sign the SAME content: key_id "demo", key_version 3, fields
// ["hello", "世界"] — only the key length moves.
// ---------------------------------------------------------------------------

/// Hex string of the byte sequence 0x00, 0x01, ..., n-1 (n bytes, wrapping at
/// 256). The leading 0x00 byte is deliberate: 00 is ordinary key material.
fn seq_key(n: usize) -> String {
    (0..n).map(|b| format!("{:02x}", b % 256)).collect()
}

/// Golden tag for the 63-byte key 0x00..0x3e (just under one block).
const LK_TAG_63: &str = "089231f361f5a0bbd1c3ae127f54d1a093e5675a0f53bcc5131e7e9bfa24eb8d";
/// Golden tag for the 64-byte key 0x00..0x3f (exactly one block).
const LK_TAG_64: &str = "e7f6422afb29d605ce331e2853578940225a9bb9797bed580e16f943fbb8f419";
/// Golden tag for the 65-byte key 0x00..0x40 (one byte past the block).
const LK_TAG_65: &str = "037c2e5d646e2522ba2eeb684776751feb39218c3729005d0f89ca3668ad884a";
/// Golden tag for the 131-byte key 0xaa*131 (the RFC 4231 test case 6 key,
/// clearly longer than one block).
const LK_TAG_131: &str = "4686e39e11e98e975b77659dcd4ae707c049d4d29263083969e112f913198455";

/// The four long keys together with their independent golden tags.
fn long_key_cases() -> Vec<(String, &'static str)> {
    vec![
        (seq_key(63), LK_TAG_63),
        (seq_key(64), LK_TAG_64),
        (seq_key(65), LK_TAG_65),
        ("aa".repeat(131), LK_TAG_131),
    ]
}

#[test]
fn sign_keys_around_and_beyond_the_hmac_block_match_golden_tags() {
    let fields = ["hello", "世界"];
    let mut tags = std::collections::HashSet::new();
    for (key, golden) in long_key_cases() {
        let label = format!("key-{}bytes", key.len() / 2);
        // expect_signed_record pins: exit 0, empty stderr, exactly one JSON
        // line, the six members in order, the original fields/key-id/version,
        // a 64-character lowercase hex tag, and no key material in the record.
        let rec = expect_signed_record(&label, &key, "demo", "3", &fields, golden);
        assert!(
            tags.insert(rec.tag),
            "keys of different lengths must not collapse to one tag"
        );
    }

    // Hex letter case is not key material: the uppercase spelling of the
    // 65-byte key is the same key and must produce the same record.
    let upper = seq_key(65).to_uppercase();
    expect_signed_record("key-65bytes-uppercase", &upper, "demo", "3", &fields, LK_TAG_65);
}

#[test]
fn verify_long_key_records_round_trip_and_external_records_verify() {
    let fields = ["hello", "世界"];

    // A record signed by this tool with a long key verifies with the same key:
    // exit 0, exactly {"valid":true}, empty stderr.
    for (key, _) in long_key_cases() {
        let record = sign_record_bytes(&key, "demo", "3", &fields);
        let out = run_verify(&key, &record);
        assert_eq!(
            out.status.code(),
            Some(0),
            "key of {} bytes: stderr={:?}",
            key.len() / 2,
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":true}\n");
        assert!(out.stderr.is_empty());
    }

    // A record produced OUTSIDE this tool, carrying the independent golden
    // tag for the 131-byte key, verifies just the same: compatibility is
    // anchored to the published format-1 contract, not to self-consistency.
    let key131 = "aa".repeat(131);
    let external = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"demo\",\"key_version\":3,\"fields\":[\"hello\",\"世界\"],\"tag\":\"{LK_TAG_131}\"}}"
    );
    let out = run_verify(&key131, external.as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(out.stderr.is_empty());

    // The same external record re-formatted (members reordered, JSON
    // whitespace padding) still verifies under the long key.
    let pretty = format!(
        "  {{\n    \"tag\" : \"{LK_TAG_131}\",\n    \"fields\" : [ \"hello\" , \"世界\" ],\n    \"key_version\" : 3,\n    \"key_id\" : \"demo\",\n    \"algorithm\" : \"HMAC-SHA256\",\n    \"format\" : 1\n  }}\r\n"
    );
    let out = run_verify(&key131, pretty.as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(out.stderr.is_empty());
}

#[test]
fn verify_long_key_tail_bytes_and_truncation_are_mismatch_not_corruption() {
    let key131 = "aa".repeat(131);
    let record = sign_record_bytes(&key131, "demo", "3", &["hello", "世界"]);

    // Every key below is well-formed hex, so the record stays structurally
    // legal: the outcome must be a plain mismatch (exit 1, {"valid":false},
    // empty stderr), never a corrupt-input exit 2.
    let wrong_keys = [
        // Same first 64 bytes, different content beyond the block boundary:
        // the tail of a long key is key material, not padding to ignore.
        format!("{}{}", "aa".repeat(64), "bb".repeat(67)),
        // The key truncated to exactly one 64-byte block is a DIFFERENT key.
        "aa".repeat(64),
        // A single byte flipped inside the first block.
        format!("ab{}", "aa".repeat(130)),
    ];
    for key in wrong_keys {
        let out = run_verify(&key, &record);
        assert_eq!(
            out.status.code(),
            Some(1),
            "key must mismatch, not error: stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":false}\n");
        assert!(out.stderr.is_empty(), "mismatch must be silent on stderr");
    }

    // The 65th byte must not be dropped: a record signed with the 65-byte key
    // must not verify under its 64-byte truncation, and the 64-byte key's
    // record must not verify under the 65-byte key.
    let rec65 = sign_record_bytes(&seq_key(65), "demo", "3", &["hello", "世界"]);
    let rec64 = sign_record_bytes(&seq_key(64), "demo", "3", &["hello", "世界"]);
    for (record, key) in [(&rec65, seq_key(64)), (&rec64, seq_key(65))] {
        let out = run_verify(&key, record);
        assert_eq!(
            out.status.code(),
            Some(1),
            "truncating/extending the key must mismatch: stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":false}\n");
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn long_keys_still_must_be_well_formed_hex() {
    // Length never relaxes the input rules: a long key with a non-hex
    // character (here deep in the tail, past byte 64) or with an odd number
    // of digits is still a usage error — exit 2, empty stdout, and a stderr
    // that names --key and the hex problem without echoing the key.
    let long = seq_key(131); // distinctive content: 000102...7f808182...
    let mut nonhex = long.clone();
    nonhex.replace_range(200..201, "g");
    let odd = &long[..long.len() - 1];

    for bad in [&nonhex, odd] {
        let stderr = expect_usage_error(&["--key", bad, "--key-id", "id", "--key-version", "1"]);
        assert!(stderr.contains("--key"), "stderr must name --key: {stderr}");
        assert!(
            stderr.contains("hexadecimal"),
            "stderr must describe the key format problem: {stderr}"
        );
        assert!(!stderr.contains(bad), "stderr echoed the rejected key: {stderr}");
        assert!(
            !stderr.contains(&long[..32]),
            "stderr echoed a fragment of the key: {stderr}"
        );
    }

    // verify applies the same key validation before it ever looks at stdin.
    let record = sign_record_bytes(&seq_key(65), "id", "1", &["x"]);
    for bad in [&nonhex, odd] {
        let stderr = expect_verify_invalid(&record, &["--key", bad]);
        assert!(stderr.contains("--key"), "stderr must name --key: {stderr}");
        assert!(
            stderr.contains("hexadecimal"),
            "stderr must describe the key format problem: {stderr}"
        );
        assert!(!stderr.contains(bad), "stderr echoed the rejected key: {stderr}");
        assert!(
            !stderr.contains(&long[..32]),
            "stderr echoed a fragment of the key: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// Unicode normalization: "looks the same" is not "is the same message".
//
// Format 1 authenticates the raw UTF-8 text of each field. The single
// character é (U+00E9, precomposed) and the two-character sequence
// e + U+0301 (letter e followed by COMBINING ACUTE ACCENT) may render
// identically, but they are different byte sequences and therefore different
// messages. Both are legal text: each must sign and verify on its own, and
// neither may be rewritten into the other for the sake of display.
//
// Every golden tag below was computed independently with Python's
// hmac/hashlib/struct straight from the format-1 byte contract in README.md,
// never derived from this crate's own HMAC code:
//
//   precomposed ["\u00e9"]        -> c3 a9          (2 UTF-8 bytes)
//   composed    ["e\u0301"]       -> 65 cc 81       (3 UTF-8 bytes)
//   accent alone ["\u0301"]       -> cc 81
//   two fields  ["e", "\u0301"]  -> 65 / cc 81
// ---------------------------------------------------------------------------

/// é as one precomposed character (U+00E9).
const NFC_E: &str = "\u{00e9}";
/// e followed by U+0301 COMBINING ACUTE ACCENT (two characters).
const NFD_E: &str = "e\u{0301}";
/// U+0301 COMBINING ACUTE ACCENT on its own.
const ACCENT: &str = "\u{0301}";

const NORM_KEY: &str = "00ff";
const NORM_KID: &str = "id";
const NORM_VERSION: &str = "1";

/// Golden tag for fields [é] (precomposed, U+00E9).
const TAG_PRECOMPOSED: &str = "0a0d1264786153d4cee915619413d30a55e0886069d13a4aaccb0290bd20b8de";
/// Golden tag for fields [e + U+0301] (composed sequence).
const TAG_COMPOSED: &str = "d7698cf682d11e71b08655ebab11056fbec33480f6665daa2104156866663f01";
/// Golden tag for fields [U+00E9, "e"+U+0301, U+00E9] (precomposed repeated).
const TAG_BOTH_REPEAT_PRE: &str = "b645b9145638eab0d912c471bc6522f1ddae765b0421078c7f8a21ae58b0739f";
/// Golden tag for fields ["e"+U+0301, U+00E9, "e"+U+0301] (composed repeated).
const TAG_BOTH_REPEAT_COM: &str = "26270edcd121de31632d60e738d23563b2534ec2b1180e81bce9ad0e5d69ea65";
/// Golden tag for fields [U+0301] (combining accent alone).
const TAG_ACCENT_ALONE: &str = "02fea2ee40a762e86d37a466529969f7a1d3f16912e24dd7612c200960352113";
/// Golden tag for fields ["e", U+0301] (letter and accent in separate fields).
const TAG_LETTER_AND_ACCENT: &str = "c9dc1f7e48b108b2f0f46f8151da4ea44c5f98bf2967be089cb5a31f739726a3";

#[test]
fn sign_preserves_precomposed_and_composed_spellings_as_distinct_messages() {
    // Same key, key id, version and field count; only the spelling of the
    // "same-looking" character differs. Both are legal inputs, both succeed
    // with the usual contract (exit 0, empty stderr, one JSON line), and the
    // decoded fields must be character-identical to each input.
    let pre = expect_signed_record(
        "precomposed-e",
        NORM_KEY, NORM_KID, NORM_VERSION, &[NFC_E],
        TAG_PRECOMPOSED,
    );
    let com = expect_signed_record(
        "composed-e",
        NORM_KEY, NORM_KID, NORM_VERSION, &[NFD_E],
        TAG_COMPOSED,
    );

    // The two spellings are different messages: different authenticated bytes,
    // different tags. Neither may be normalized into the other.
    assert_ne!(pre.tag, com.tag);
    assert_eq!(pre.fields, vec![NFC_E.to_string()]);
    assert_eq!(com.fields, vec![NFD_E.to_string()]);

    // The wire form keeps the original bytes: the precomposed record carries
    // c3 a9 and never grows a combining accent; the composed record carries
    // 65 cc 81 and is never folded into the single precomposed character.
    let pre_raw = run_sign(NORM_KEY, NORM_KID, NORM_VERSION, &[NFC_E]).stdout;
    let com_raw = run_sign(NORM_KEY, NORM_KID, NORM_VERSION, &[NFD_E]).stdout;
    assert!(
        pre_raw.windows(NFC_E.len()).any(|w| w == NFC_E.as_bytes()),
        "precomposed record must carry U+00E9 as raw UTF-8: {pre_raw:?}"
    );
    assert!(
        !pre_raw.windows(NFD_E.len()).any(|w| w == NFD_E.as_bytes()),
        "precomposed record must not contain the composed sequence: {pre_raw:?}"
    );
    assert!(
        com_raw.windows(NFD_E.len()).any(|w| w == NFD_E.as_bytes()),
        "composed record must carry e + U+0301 as raw UTF-8: {com_raw:?}"
    );
    assert!(
        !com_raw.windows(NFC_E.len()).any(|w| w == NFC_E.as_bytes()),
        "composed record must not contain the precomposed character: {com_raw:?}"
    );

    // Each record verifies under the original key with its own tag.
    for record in [pre_raw, com_raw] {
        let out = run_verify(NORM_KEY, &record);
        assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.stdout, b"{\"valid\":true}\n");
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn sign_keeps_both_spellings_and_repeats_in_order_without_merging() {
    // A record containing BOTH spellings, with one of them repeated: input
    // order and every occurrence must survive; the look-alike characters must
    // not be merged, deduplicated or rewritten.
    let rec = expect_signed_record(
        "both-repeat-precomposed",
        NORM_KEY, NORM_KID, NORM_VERSION,
        &[NFC_E, NFD_E, NFC_E],
        TAG_BOTH_REPEAT_PRE,
    );
    assert_eq!(
        rec.fields,
        vec![NFC_E.to_string(), NFD_E.to_string(), NFC_E.to_string()]
    );

    // Repeating the composed spelling instead is a different message.
    let rec2 = expect_signed_record(
        "both-repeat-composed",
        NORM_KEY, NORM_KID, NORM_VERSION,
        &[NFD_E, NFC_E, NFD_E],
        TAG_BOTH_REPEAT_COM,
    );
    assert_eq!(
        rec2.fields,
        vec![NFD_E.to_string(), NFC_E.to_string(), NFD_E.to_string()]
    );
    assert_ne!(rec.tag, rec2.tag);
}

#[test]
fn verify_respelled_unicode_escapes_keep_the_original_tag_valid() {
    // U+00E9 written directly or as \u00e9, and the composed sequence written
    // directly or as e\u0301, decode to the same character sequence: the
    // original tag stays valid (exit 0, {"valid":true}, empty stderr). This
    // is a JSON spelling change, not a message change.
    let pre_record = sign_record_bytes(NORM_KEY, NORM_KID, NORM_VERSION, &[NFC_E]);
    let pre_body = String::from_utf8(pre_record).unwrap();
    let pre_escaped = pre_body.replacen(NFC_E, "\\u00e9", 1);
    assert_ne!(pre_escaped, pre_body, "the escape rewrite must change the wire text");

    let com_record = sign_record_bytes(NORM_KEY, NORM_KID, NORM_VERSION, &[NFD_E]);
    let com_body = String::from_utf8(com_record).unwrap();
    let com_escaped = com_body.replacen(NFD_E, "e\\u0301", 1);
    assert_ne!(com_escaped, com_body, "the escape rewrite must change the wire text");

    for (label, text) in [
        ("precomposed direct", pre_body.as_str()),
        ("precomposed escaped", pre_escaped.as_str()),
        ("composed direct", com_body.as_str()),
        ("composed escaped", com_escaped.as_str()),
    ] {
        let out = run_verify(NORM_KEY, text.as_bytes());
        assert_eq!(
            out.status.code(),
            Some(0),
            "{label}: stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":true}\n", "{label}");
        assert!(out.stderr.is_empty(), "{label}");
    }

    // Records produced entirely OUTSIDE this tool, carrying the independent
    // Python golden tags, verify the same way — in both direct and fully
    // escaped ASCII-only spellings. Compatibility is anchored to the
    // published format-1 contract, not to self-consistency.
    let external_pre = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"{NORM_KID}\",\"key_version\":1,\"fields\":[\"{NFC_E}\"],\"tag\":\"{TAG_PRECOMPOSED}\"}}"
    );
    let external_pre_escaped = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"{NORM_KID}\",\"key_version\":1,\"fields\":[\"\\u00e9\"],\"tag\":\"{TAG_PRECOMPOSED}\"}}"
    );
    assert!(external_pre_escaped.is_ascii());
    let external_com = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"{NORM_KID}\",\"key_version\":1,\"fields\":[\"{NFD_E}\"],\"tag\":\"{TAG_COMPOSED}\"}}"
    );
    let external_com_escaped = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"{NORM_KID}\",\"key_version\":1,\"fields\":[\"e\\u0301\"],\"tag\":\"{TAG_COMPOSED}\"}}"
    );
    assert!(external_com_escaped.is_ascii());
    for (label, text) in [
        ("external precomposed direct", external_pre),
        ("external precomposed escaped", external_pre_escaped),
        ("external composed direct", external_com),
        ("external composed escaped", external_com_escaped),
    ] {
        let out = run_verify(NORM_KEY, text.as_bytes());
        assert_eq!(
            out.status.code(),
            Some(0),
            "{label}: stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":true}\n", "{label}");
        assert!(out.stderr.is_empty(), "{label}");
    }
}

#[test]
fn verify_swapping_precomposed_and_composed_is_a_mismatch_in_both_directions() {
    // Replacing ONLY the precomposed character with the composed sequence (or
    // vice versa) while keeping the original tag and every other member: the
    // record stays structurally legal JSON, but the authenticated message
    // changed, so the result must be exit 1, {"valid":false}, empty stderr —
    // never exit 2 and never valid. Both directions, and both the raw-UTF-8
    // and the \u00e9-spelled replacement, obey this rule.
    let pre_body = String::from_utf8(sign_record_bytes(NORM_KEY, NORM_KID, NORM_VERSION, &[NFC_E]))
        .unwrap();
    let com_body = String::from_utf8(sign_record_bytes(NORM_KEY, NORM_KID, NORM_VERSION, &[NFD_E]))
        .unwrap();

    let swapped: Vec<(&str, String)> = vec![
        // precomposed record, field rewritten to the composed sequence
        ("pre->com raw", pre_body.replacen(NFC_E, NFD_E, 1)),
        ("pre->com escaped", pre_body.replacen(NFC_E, "e\\u0301", 1)),
        // composed record, field rewritten to the precomposed character
        ("com->pre raw", com_body.replacen(NFD_E, NFC_E, 1)),
        ("com->pre escaped", com_body.replacen(NFD_E, "\\u00e9", 1)),
    ];
    for (label, text) in &swapped {
        let out = run_verify(NORM_KEY, text.as_bytes());
        assert_eq!(
            out.status.code(),
            Some(1),
            "{label}: expected mismatch (exit 1), stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":false}\n", "{label}");
        assert!(out.stderr.is_empty(), "{label}: mismatch must be silent on stderr");
    }
}

#[test]
fn combining_accent_alone_and_split_fields_are_legal_distinct_messages() {
    // A combining accent with no preceding letter is still legal text: as a
    // field on its own it signs and verifies like any other message, not a
    // format error.
    let alone = expect_signed_record(
        "accent-alone",
        NORM_KEY, NORM_KID, NORM_VERSION, &[ACCENT],
        TAG_ACCENT_ALONE,
    );
    assert_eq!(alone.fields, vec![ACCENT.to_string()]);
    let alone_raw = run_sign(NORM_KEY, NORM_KID, NORM_VERSION, &[ACCENT]).stdout;
    let out = run_verify(NORM_KEY, &alone_raw);
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(out.stderr.is_empty());

    // An external record carrying the accent as an escape with the golden tag
    // verifies too: a lone combining mark is not corruption.
    let external_alone = format!(
        "{{\"format\":1,\"algorithm\":\"HMAC-SHA256\",\"key_id\":\"{NORM_KID}\",\"key_version\":1,\"fields\":[\"\\u0301\"],\"tag\":\"{TAG_ACCENT_ALONE}\"}}"
    );
    assert!(external_alone.is_ascii());
    let out = run_verify(NORM_KEY, external_alone.as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(out.stderr.is_empty());

    // Letter and accent in TWO fields is a different message from the
    // composed sequence in ONE field: field boundaries are authenticated, so
    // the two forms must not share a tag.
    let split = expect_signed_record(
        "letter-and-accent-two-fields",
        NORM_KEY, NORM_KID, NORM_VERSION, &["e", ACCENT],
        TAG_LETTER_AND_ACCENT,
    );
    assert_eq!(split.fields, vec!["e".to_string(), ACCENT.to_string()]);
    assert_ne!(split.tag, TAG_COMPOSED);

    // The split record verifies with its own tag...
    let split_raw = run_sign(NORM_KEY, NORM_KID, NORM_VERSION, &["e", ACCENT]).stdout;
    let out = run_verify(NORM_KEY, &split_raw);
    assert_eq!(out.status.code(), Some(0), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(out.stderr.is_empty());

    // ...but crossing the boundary in either direction with the other form's
    // tag is a plain mismatch, not corrupt input.
    let split_body = String::from_utf8(split_raw).unwrap();
    let merged = split_body.replacen("\"e\",\"\u{0301}\"", "\"e\u{0301}\"", 1);
    assert_ne!(merged, split_body, "the field merge must change the record");
    let com_body = String::from_utf8(sign_record_bytes(NORM_KEY, NORM_KID, NORM_VERSION, &[NFD_E]))
        .unwrap();
    let split_apart = com_body.replacen("\"e\u{0301}\"", "\"e\",\"\u{0301}\"", 1);
    assert_ne!(split_apart, com_body, "the field split must change the record");
    for (label, text) in [("merged fields, old tag", merged), ("split field, old tag", split_apart)] {
        let out = run_verify(NORM_KEY, text.as_bytes());
        assert_eq!(
            out.status.code(),
            Some(1),
            "{label}: expected mismatch (exit 1), stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"{\"valid\":false}\n", "{label}");
        assert!(out.stderr.is_empty(), "{label}");
    }
}
