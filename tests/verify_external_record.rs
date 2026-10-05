//! Regression coverage for `verify` against records that an **external**
//! program could build straight from the published format-1 contract —
//! records that `sign` can never emit here, because some of their text cannot
//! be passed as a command-line argument at all.
//!
//! The central case is a field containing U+0000: a NUL cannot travel through
//! `argv`, so no existing end-to-end test ever exercises a verified record
//! whose decoded text contains one. These tests hand-write the JSON record
//! byte-by-byte (NUL appears only as the legal JSON escape `\u0000`) and feed
//! it to the compiled `verify` binary.
//!
//! Independence of the expected verdict. The tag is a **golden** value
//! computed outside this crate with Python's hmac/hashlib/struct, directly
//! from the format-1 byte layout documented in README.md — not produced by
//! this crate's `sign`, so a shared sign/verify bug cannot make these pass.
//! The same Python oracle reproduces the already-published golden tag
//! `2372588c…` (key `deadbeef`, id `id`, version 4294967295, field `世界🙂`)
//! byte-for-byte, which pins the oracle to the public contract:
//!
//! ```python
//! import hmac, hashlib, struct
//! def encode(key_id, version, fields):
//!     out = b"authnote-sign-v1"
//!     kb = key_id.encode()
//!     out += struct.pack(">Q", len(kb)) + kb
//!     out += struct.pack(">I", version)
//!     out += struct.pack(">Q", len(fields))
//!     for f in fields:
//!         fb = f.encode(); out += struct.pack(">Q", len(fb)) + fb
//!     return out
//! tag = hmac.new(bytes.fromhex(KEY), encode(kid, 42, fields),
//!                hashlib.sha256).hexdigest()
//! # kid   = "密钥🗝️一\n二"
//! # fields[0] = "前缀\u0000后缀"  (NUL flanked by text on both sides)
//! # fields[1] = "\u0000"
//! # fields[2..3] = "重复🙂", "重复🙂"  (a repeated field)
//! # fields[4] = ""                   (an empty field)
//! # fields[5] = "第一行\n第二行\n"
//! # fields[6] = "世🙂"
//! # -> f92b10fee8eebcd06d014f1677b968bb9ed29e3030353fe7dad4431362a5f4f4
//! ```
//!
//! What is guaranteed here, end to end through the real process:
//!   * direct CJK/emoji text, `\uXXXX` escapes and UTF-16 surrogate pairs
//!     that decode to the same text all authenticate identically;
//!   * `\n` and `\u000a` are equivalent newline spellings; NUL is `\u0000`;
//!   * member reordering and layout whitespace never require a new tag;
//!   * genuinely changed content (NUL deleted, newline turned into the two
//!     characters `\` `n`, duplicate/empty fields dropped, order changed)
//!     invalidates the old tag -> {"valid":false}, exit 1;
//!   * truncated Unicode escapes and broken surrogate pairs are corrupt
//!     input -> exit 2, empty stdout, a stderr explanation that never echoes
//!     the record, the key or the rejected value.

use std::io::Write;
use std::process::{Command, Output, Stdio};

// ---------------------------------------------------------------------------
// Harness around the compiled binary.
// ---------------------------------------------------------------------------

fn authnote() -> Command {
    Command::new(env!("CARGO_BIN_EXE_authnote"))
}

/// Feed raw bytes (which may contain NUL) as the record on stdin.
fn run_verify(key: &str, input: &[u8]) -> Output {
    let mut child = authnote()
        .arg("verify")
        .arg("--key")
        .arg(key)
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

const KEY: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

/// Independent Python golden tag for the canonical decoded content below.
const GOLDEN_TAG: &str = "f92b10fee8eebcd06d014f1677b968bb9ed29e3030353fe7dad4431362a5f4f4";

// UTF-8 byte lengths and field count printed by the independent oracle; they
// are what the u64 length prefixes must encode, so an implementation that
// truncates at NUL, counts characters instead of bytes, or merges/drops
// fields cannot authenticate the record.
const EXPECTED_KID_UTF8_LEN: usize = 20;
const EXPECTED_FIELD_UTF8_LENS: &[usize] = &[13, 1, 10, 10, 0, 20, 7];

// ---------------------------------------------------------------------------
// Record assembly from raw JSON string-content bytes.
//
// A `Rec` stores the *already-encoded JSON spelling* of each string (without
// its surrounding quotes), so the same decoded text can be expressed in
// several different legal ways: literal CJK/emoji bytes, `\uXXXX` escapes,
// surrogate pairs, `\n` vs `\u000a`, ... . NUL therefore appears on the wire
// as the six ASCII bytes of `\u0000`; the NUL lives only in the decoded text.
// ---------------------------------------------------------------------------

struct Rec {
    key_id: Vec<u8>,
    version: u32,
    fields: Vec<Vec<u8>>,
    tag: String,
}

fn quote(content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 2);
    v.push(b'"');
    v.extend_from_slice(content);
    v.push(b'"');
    v
}

impl Rec {
    fn canonical(tag: &str) -> Rec {
        Rec {
            key_id: kid_short_newline(),
            version: 42,
            fields: vec![
                f1_nul_escaped_literal_cjk(),
                b"\\u0000".to_vec(),
                f3_literal(),
                f3_literal(),
                Vec::new(),
                f6_short_newline(),
                f7_literal(),
            ],
            tag: tag.to_string(),
        }
    }

    /// Emit the record as JSON. `pretty` reverses the member order and adds
    /// layout whitespace (spaces, tabs and real newlines between tokens;
    /// string-internal newlines stay escaped as JSON requires).
    fn emit(&self, pretty: bool) -> Vec<u8> {
        let fields: Vec<Vec<u8>> = self.fields.iter().map(|c| quote(c)).collect();
        let sep = if pretty { ", " } else { "," };
        let fields_body = fields
            .iter()
            .map(|f| f.as_slice())
            .collect::<Vec<_>>()
            .join(sep.as_bytes());

        let alg = b"\"HMAC-SHA256\"".to_vec();
        let mut members: Vec<(&[u8], Vec<u8>)> = vec![
            (b"format", b"1".to_vec()),
            (b"algorithm", alg),
            (b"key_id", quote(&self.key_id)),
            (b"key_version", self.version.to_string().into_bytes()),
            (b"fields", [&b"["[..], &fields_body[..], b"]"].concat()),
            (b"tag", quote(self.tag.as_bytes())),
        ];
        if pretty {
            members.reverse();
        }

        let (open, before_key, colon, after_val, close) = if pretty {
            ("{\n  ", "\n  ", ": ", ",", "\n}")
        } else {
            ("{", "", ":", ",", "}")
        };

        let mut out = Vec::new();
        out.extend_from_slice(open.as_bytes());
        for (i, (name, value)) in members.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(after_val.as_bytes());
                out.extend_from_slice(before_key.as_bytes());
            }
            out.extend_from_slice(&quote(name));
            out.extend_from_slice(colon.as_bytes());
            out.extend_from_slice(value);
        }
        out.extend_from_slice(close.as_bytes());
        if pretty {
            // Surrounding JSON whitespace plus tabs/CR, all legal framing.
            let mut padded = Vec::new();
            padded.extend_from_slice(b" \t\n");
            padded.append(&mut out);
            padded.extend_from_slice(b"\r\n  ");
            padded
        } else {
            out
        }
    }
}

// --- JSON spellings of the decoded content (all decode to the same text) ---

/// "密钥🗝️一" + newline (short escape) + "二"
fn kid_short_newline() -> Vec<u8> {
    let mut v = "密钥🗝️一".as_bytes().to_vec();
    v.extend_from_slice(b"\\n");
    v.extend_from_slice("二".as_bytes());
    v
}

/// Mixed spelling: "密" literal, "钥" as 钥, 🗝 literal, the U+FE0F
/// variation selector escaped, newline as the short escape.
fn kid_mixed() -> Vec<u8> {
    let mut v = "密".as_bytes().to_vec();
    v.extend_from_slice(b"\\u94a5");
    v.extend_from_slice("🗝".as_bytes());
    v.extend_from_slice(b"\\ufe0f");
    v.extend_from_slice("一".as_bytes());
    v.extend_from_slice(b"\\n");
    v.extend_from_slice("二".as_bytes());
    v
}

/// Every non-ASCII char as a Unicode escape: 密钥, the 🗝 surrogate pair
/// (U+1F5DD), U+FE0F, 一/二; newline spelled as \u000a.
fn kid_all_escaped_unicode_newline() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"\\u5bc6\\u94a5\\ud83d\\udddd\\ufe0f\\u4e00\\u000a\\u4e8c");
    v
}

/// Field 0: literal CJK flanking the escaped NUL.
fn f1_nul_escaped_literal_cjk() -> Vec<u8> {
    let mut v = "前缀".as_bytes().to_vec();
    v.extend_from_slice(b"\\u0000");
    v.extend_from_slice("后缀".as_bytes());
    v
}

/// Field 0: same decoded text, CJK also written via \u escapes.
fn f1_all_escaped() -> Vec<u8> {
    b"\\u524d\\u7f00\\u0000\\u540e\\u7f00".to_vec()
}

/// "重复🙂" with literal multibyte text.
fn f3_literal() -> Vec<u8> {
    "重复🙂".as_bytes().to_vec()
}

/// Same decoded text using \u escapes and the 🙂 surrogate pair.
fn f3_escaped() -> Vec<u8> {
    let mut v = b"\\u91cd\\u590d".to_vec();
    v.extend_from_slice(b"\\ud83d\\ude42");
    v
}

/// "第一行\n第二行\n" — real newlines as the short `\n` escape.
fn f6_short_newline() -> Vec<u8> {
    let mut v = "第一行".as_bytes().to_vec();
    v.extend_from_slice(b"\\n");
    v.extend_from_slice("第二行".as_bytes());
    v.extend_from_slice(b"\\n");
    v
}

/// Same decoded newlines spelled as `\u000a`.
fn f6_unicode_newline() -> Vec<u8> {
    let mut v = "第一行".as_bytes().to_vec();
    v.extend_from_slice(b"\\u000a");
    v.extend_from_slice("第二行".as_bytes());
    v.extend_from_slice(b"\\u000a");
    v
}

/// "世🙂" fully literal.
fn f7_literal() -> Vec<u8> {
    "世🙂".as_bytes().to_vec()
}

/// "世" escaped, emoji literal.
fn f7_cjk_escaped() -> Vec<u8> {
    let mut v = b"\\u4e16".to_vec();
    v.extend_from_slice("🙂".as_bytes());
    v
}

/// "世" literal, emoji as its surrogate pair.
fn f7_emoji_surrogate() -> Vec<u8> {
    let mut v = "世".as_bytes().to_vec();
    v.extend_from_slice(b"\\ud83d\\ude42");
    v
}

/// Both escaped.
fn f7_both_escaped() -> Vec<u8> {
    b"\\u4e16\\ud83d\\ude42".to_vec()
}

// ---------------------------------------------------------------------------
// Tiny decoder used only to validate the *test fixtures themselves*: it shows
// what text each hand-written JSON string decodes to, independent of the
// binary under test. Supports exactly the escapes these fixtures use.
// ---------------------------------------------------------------------------

fn decode_json_string_content(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    fn hex4(s: &[u8], i: &mut usize) -> u32 {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = s[*i] as char;
            v = v * 16 + c.to_digit(16).unwrap_or_else(|| panic!("bad hex in fixture escape"));
            *i += 1;
        }
        v
    }
    while i < src.len() {
        match src[i] {
            b'\\' => {
                i += 1;
                match src[i] {
                    b'n' => {
                        out.push(b'\n');
                        i += 1;
                    }
                    b'\\' => {
                        out.push(b'\\');
                        i += 1;
                    }
                    b'u' => {
                        i += 1;
                        let hi = hex4(src, &mut i);
                        let c = if (0xD800..=0xDBFF).contains(&hi) {
                            assert_eq!(&src[i..i + 2], b"\\u", "fixture must pair surrogates");
                            i += 2;
                            let lo = hex4(src, &mut i);
                            assert!((0xDC00..=0xDFFF).contains(&lo));
                            char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)).unwrap()
                        } else {
                            char::from_u32(hi).unwrap()
                        };
                        out.extend_from_slice(c.to_string().as_bytes());
                    }
                    other => panic!("fixture uses unsupported escape \\{other}"),
                }
            }
            // Literal multibyte UTF-8 (and any other plain byte) passes through.
            _ => {
                out.push(src[i]);
                i += 1;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Outcome helpers.
// ---------------------------------------------------------------------------

fn expect_valid(input: &[u8]) {
    let out = run_verify(KEY, input);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0, got {:?}; stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"{\"valid\":true}\n", "stdout must be exactly the one valid line");
    assert!(
        out.stderr.is_empty(),
        "stderr must be empty, got {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn expect_mismatch(input: &[u8]) {
    let out = run_verify(KEY, input);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1, got {:?}; stderr={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"{\"valid\":false}\n");
    assert!(
        out.stderr.is_empty(),
        "stderr must be empty on mismatch, got {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn expect_corrupt(input: &[u8]) -> String {
    let out = run_verify(KEY, input);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2, got {:?}; stdout={:?}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(out.stdout.is_empty(), "stdout must be empty on corrupt input");
    let stderr = String::from_utf8(out.stderr).expect("stderr must be valid UTF-8");
    assert!(!stderr.trim().is_empty(), "stderr must explain the format problem");

    // The explanation must not echo the key, the record content (its Chinese
    // text), a raw NUL, or the rejected record verbatim.
    assert!(!stderr.contains(KEY), "stderr leaked the key: {stderr}");
    assert!(!stderr.contains("密钥"), "stderr echoed key-id content: {stderr}");
    assert!(!stderr.contains("前缀"), "stderr echoed field content: {stderr}");
    assert!(!stderr.as_bytes().contains(&0u8), "stderr echoed a NUL: {stderr:?}");
    stderr
}

// ---------------------------------------------------------------------------
// Fixture sanity: the hand-written spellings really decode to the documented
// text, with NUL neither truncating nor collapsing to empty, and byte (not
// character) lengths matching the independent oracle.
// ---------------------------------------------------------------------------

#[test]
fn fixtures_decode_to_the_documented_text() {
    let rec = Rec::canonical(GOLDEN_TAG);

    let kid = decode_json_string_content(&rec.key_id);
    assert_eq!(kid.len(), EXPECTED_KID_UTF8_LEN);
    assert_eq!(kid, "密钥🗝️一\n二".as_bytes());

    let decoded: Vec<Vec<u8>> = rec
        .fields
        .iter()
        .map(|c| decode_json_string_content(c))
        .collect();
    let lens: Vec<usize> = decoded.iter().map(Vec::len).collect();
    assert_eq!(lens, EXPECTED_FIELD_UTF8_LENS);
    assert_eq!(decoded.len(), 7);

    // NUL is flanked by text on both sides and survives as one real byte.
    assert_eq!(decoded[0], "前缀\u{0000}后缀".as_bytes());
    assert_eq!(decoded[0].len(), "前缀".len() + 1 + "后缀".len());
    // A one-NUL field is a non-empty field, distinct from the empty one.
    assert_eq!(decoded[1], b"\x00");
    assert_ne!(decoded[1], b"");
    assert_eq!(decoded[4], b"");
    // Repeated fields are kept twice, in order; newlines decode to 0x0A.
    assert_eq!(decoded[2], decoded[3]);
    assert_eq!(decoded[5], "第一行\n第二行\n".as_bytes());
    assert_eq!(decoded[6], "世🙂".as_bytes());

    // The alternative spellings decode to byte-identical text.
    assert_eq!(decode_json_string_content(&kid_mixed()), kid);
    assert_eq!(decode_json_string_content(&kid_all_escaped_unicode_newline()), kid);
    assert_eq!(decode_json_string_content(&f1_all_escaped()), decoded[0]);
    assert_eq!(decode_json_string_content(&f3_escaped()), decoded[2]);
    assert_eq!(decode_json_string_content(&f6_unicode_newline()), decoded[5]);
    assert_eq!(decode_json_string_content(&f7_cjk_escaped()), decoded[6]);
    assert_eq!(decode_json_string_content(&f7_emoji_surrogate()), decoded[6]);
    assert_eq!(decode_json_string_content(&f7_both_escaped()), decoded[6]);
}

// ---------------------------------------------------------------------------
// Success: externally produced records authenticate with the golden tag.
// ---------------------------------------------------------------------------

#[test]
fn external_record_with_nul_cjk_emoji_and_newline_verifies() {
    // The canonical (mostly literal) spelling, compact layout.
    expect_valid(&Rec::canonical(GOLDEN_TAG).emit(false));
}

#[test]
fn representation_member_order_and_whitespace_changes_keep_the_tag_valid() {
    // Every row decodes to the exact same authenticated text; only the JSON
    // spelling differs. None of these must require regenerating the tag.
    let mut representations: Vec<Rec> = Vec::new();

    // 1. Literal CJK/emoji, short newline escapes, pretty + reordered.
    representations.push(Rec::canonical(GOLDEN_TAG));

    // 2. Fully \u-escaped (CJK + emoji surrogate pairs), newlines as \u000a.
    representations.push(Rec {
        key_id: kid_all_escaped_unicode_newline(),
        version: 42,
        fields: vec![
            f1_all_escaped(),
            b"\\u0000".to_vec(),
            f3_escaped(),
            f3_escaped(),
            Vec::new(),
            f6_unicode_newline(),
            f7_both_escaped(),
        ],
        tag: GOLDEN_TAG.to_string(),
    });

    // 3. Mixed: literal and escaped pieces interleaved, emoji expressed both
    //    ways across different fields.
    representations.push(Rec {
        key_id: kid_mixed(),
        version: 42,
        fields: vec![
            f1_nul_escaped_literal_cjk(),
            b"\\u0000".to_vec(),
            f3_literal(),
            f3_escaped(),
            Vec::new(),
            f6_short_newline(),
            f7_cjk_escaped(),
        ],
        tag: GOLDEN_TAG.to_string(),
    });

    // 4. Emoji only as surrogate pairs; CJK only as \u; short newlines.
    representations.push(Rec {
        key_id: kid_short_newline(),
        version: 42,
        fields: vec![
            f1_nul_escaped_literal_cjk(),
            b"\\u0000".to_vec(),
            f3_escaped(),
            f3_escaped(),
            Vec::new(),
            f6_short_newline(),
            f7_emoji_surrogate(),
        ],
        tag: GOLDEN_TAG.to_string(),
    });

    for (i, rec) in representations.iter().enumerate() {
        // Compact member order and pretty/reordered framing must both pass.
        expect_valid_with_context(&rec.emit(false), i, "compact");
        expect_valid_with_context(&rec.emit(true), i, "pretty-reordered");
    }
}

fn expect_valid_with_context(input: &[u8], case: usize, style: &str) {
    let out = run_verify(KEY, input);
    assert_eq!(
        out.status.code(),
        Some(0),
        "case {case} {style}: expected exit 0, stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"{\"valid\":true}\n");
    assert!(out.stderr.is_empty());
}

#[test]
fn short_and_unicode_newline_escapes_are_equivalent() {
    // Only the newline spelling differs between these two wire records; both
    // decode to fields containing real U+000A and must authenticate.
    let mut short = Rec::canonical(GOLDEN_TAG);
    short.fields[5] = f6_short_newline();
    let mut unicode = Rec::canonical(GOLDEN_TAG);
    unicode.fields[5] = f6_unicode_newline();
    expect_valid(&short.emit(false));
    expect_valid(&unicode.emit(false));
}

#[test]
fn wrong_key_on_external_record_is_a_mismatch_not_an_error() {
    let out = run_verify("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c", &Rec::canonical(GOLDEN_TAG).emit(false));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"{\"valid\":false}\n");
    assert!(out.stderr.is_empty());
}

// ---------------------------------------------------------------------------
// Mismatch: content really changes -> the old tag must fail (exit 1), even
// though every record stays structurally legal JSON.
// ---------------------------------------------------------------------------

#[test]
fn deleting_the_nul_invalidates_the_old_tag() {
    // Remove the six bytes `\u0000` from field 0: decoded text loses the NUL,
    // so the flanking Chinese now join directly. Same (old) tag -> mismatch.
    let mut rec = Rec::canonical(GOLDEN_TAG);
    let before = "前缀".as_bytes();
    let after = "后缀".as_bytes();
    let mut joined = before.to_vec();
    joined.extend_from_slice(after);
    rec.fields[0] = joined;

    // Fixture check: the NUL is genuinely gone and text is not truncated.
    let decoded = decode_json_string_content(&rec.fields[0]);
    assert_eq!(decoded, "前缀后缀".as_bytes());
    assert!(!decoded.contains(&0u8));
    assert_eq!(decoded.len(), 12);
    expect_mismatch(&rec.emit(false));
}

#[test]
fn a_nul_field_is_not_an_empty_field() {
    // Rewrite field 1's spelling from "\u0000" to "": JSON stays legal, but a
    // one-NUL field becomes a zero-length field. The old tag must not carry
    // over: U+0000 must not be treated as an empty string.
    let mut rec = Rec::canonical(GOLDEN_TAG);
    rec.fields[1] = Vec::new();
    assert_eq!(decode_json_string_content(&rec.fields[1]), b"");
    expect_mismatch(&rec.emit(false));
}

#[test]
fn turning_a_real_newline_into_backslash_n_invalidates_the_tag() {
    // Field 5 used to decode to "第一行\n第二行\n" (real newlines). Encode a
    // literal backslash followed by 'n' instead ("\\n" in JSON): the decoded
    // content now contains two pairs of the characters '\' and 'n'.
    let mut rec = Rec::canonical(GOLDEN_TAG);
    let mut literal = "第一行".as_bytes().to_vec();
    literal.extend_from_slice(b"\\\\n"); // JSON source "\n" -> '\' + 'n'
    literal.extend_from_slice("第二行".as_bytes());
    literal.extend_from_slice(b"\\\\n");
    rec.fields[5] = literal;

    let decoded = decode_json_string_content(&rec.fields[5]);
    assert_eq!(decoded, "第一行\\n第二行\\n".as_bytes());
    assert!(decoded.windows(2).any(|w| w == b"\\n"));
    assert!(!decoded.contains(&b'\n'));
    expect_mismatch(&rec.emit(false));
}

#[test]
fn duplicate_empty_and_field_order_still_participate_in_authentication() {
    // Drop one of the two identical "重复🙂" fields: the repeat is not merged.
    let mut dropped_dup = Rec::canonical(GOLDEN_TAG);
    dropped_dup.fields.remove(3);
    assert_eq!(dropped_dup.fields.len(), 6);
    expect_mismatch(&dropped_dup.emit(false));

    // Drop the single empty field: zero-length content is still content.
    let mut dropped_empty = Rec::canonical(GOLDEN_TAG);
    dropped_empty.fields.remove(4);
    assert_eq!(dropped_empty.fields.len(), 6);
    expect_mismatch(&dropped_empty.emit(false));

    // Reorder two different fields (0 and 6): arrays are ordered.
    let mut swapped = Rec::canonical(GOLDEN_TAG);
    swapped.fields.swap(0, 6);
    expect_mismatch(&swapped.emit(false));

    // Sanity control: swapping the two *identical* repeated fields changes
    // nothing and must still authenticate.
    let mut swapped_equal = Rec::canonical(GOLDEN_TAG);
    swapped_equal.fields.swap(2, 3);
    expect_valid(&swapped_equal.emit(false));
}

// ---------------------------------------------------------------------------
// Corrupt input: truncated Unicode escapes and illegal surrogate use are
// malformed JSON (exit 2), not authentication mismatches.
// ---------------------------------------------------------------------------

/// Embed a broken JSON string spelling as field 0 of an otherwise complete
/// record. Parsing fails before the tag is ever consulted.
fn record_with_broken_field(broken_content: &[u8]) -> Vec<u8> {
    let rec = Rec {
        key_id: kid_short_newline(),
        version: 42,
        fields: vec![broken_content.to_vec(), b"\\u0000".to_vec()],
        tag: GOLDEN_TAG.to_string(),
    };
    rec.emit(false)
}

#[test]
fn truncated_unicode_escapes_and_bad_surrogates_are_corrupt_input() {
    // The raw-NUL case must genuinely contain a zero byte between CJK text,
    // so it is assembled as bytes rather than written in a string literal.
    let raw_nul = {
        let mut v = "前缀".as_bytes().to_vec();
        v.push(0u8);
        v.extend_from_slice("后缀".as_bytes());
        v
    };

    let cases: Vec<Vec<u8>> = vec![
        // Truncated \u escapes (fewer than four hex digits), at various spots.
        b"abc\\u000x".to_vec(),         // three hex digits, then a non-hex char
        b"abc\\u00x".to_vec(),         // two hex digits, then a non-hex char
        b"abc\\ux".to_vec(),           // no hex digits at all
        b"abc\\u000".to_vec(),         // end of string right after three digits
        // High surrogate not completed into a pair.
        b"a\\ud83d".to_vec(),          // high surrogate at end of string
        b"a\\ud83d\\ud".to_vec(),      // low surrogate escape truncated
        b"a\\ud83d\\u".to_vec(),       // low surrogate marker truncated
        // High surrogate followed by something that is not a low surrogate.
        b"a\\ud83d\\u0041b".to_vec(),  // ... followed by 'A'
        b"a\\ud83d\\u4e16b".to_vec(),  // ... followed by a non-surrogate BMP char
        // Lone low surrogate.
        b"\\ude42x".to_vec(),
        raw_nul,
    ];

    for (i, broken) in cases.iter().enumerate() {
        let rec = record_with_broken_field(broken.as_slice());
        let stderr = expect_corrupt(&rec);
        // Each must be rejected as a JSON/text formatting problem.
        assert!(
            stderr.to_lowercase().contains("json") || stderr.contains("surrogate") || stderr.contains("escape") || stderr.contains("control"),
            "case {i}: stderr should describe the text-format problem, got {stderr:?}"
        );
    }
}

#[test]
fn corrupt_escape_in_key_id_is_likewise_rejected_without_echo() {
    let mut rec = Rec::canonical(GOLDEN_TAG);
    let mut kid = "密钥".as_bytes().to_vec();
    kid.extend_from_slice(b"\\ud83d"); // lone high surrogate in the key id
    rec.key_id = kid;
    let stderr = expect_corrupt(&rec.emit(false));
    assert!(!stderr.contains(GOLDEN_TAG), "stderr must not echo the record/tag: {stderr}");
}
