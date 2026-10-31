//! The broker's canonical query form for the token route.
//!
//! The http-authz/v1 profile compares the raw query byte for byte. This app
//! also requires the query to be in one canonical form, so each scope has
//! exactly one query string and a policy that lists or denies exact query
//! strings cannot be sidestepped by reordering or re-encoding:
//!
//! - Only RFC 3986 unreserved bytes (`A-Z a-z 0-9 - . _ ~`) appear literally.
//!   Every other byte is `%XX` with uppercase hex.
//! - Split on `&`, then each component on its first `=`; a component without
//!   `=` has an empty value. `+` is a literal plus sign. Empty components and
//!   empty keys are errors. Pairs are sorted by key bytes, then value bytes,
//!   and duplicates are kept.
//!
//! Other implementations should run the same vectors in `testdata/scope-query.json`.

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Percent-encode every byte outside the unreserved set, with uppercase hex.
fn percent_encode_into(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if is_unreserved(b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode `%XX` escapes. Every other byte, including `+`, is literal.
///
/// Returns `None` for a truncated or non-hex escape.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hi = bytes.get(i + 1).copied().and_then(hex_val);
            let lo = bytes.get(i + 2).copied().and_then(hex_val);
            match (hi, lo) {
                (Some(h), Some(l)) => out.push((h << 4) | l),
                _ => return None,
            }
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Some(out)
}

pub(crate) type BytePairs = Vec<(Vec<u8>, Vec<u8>)>;

pub(crate) fn decoded_pairs(raw: &str) -> Option<BytePairs> {
    if raw.is_empty() {
        return Some(Vec::new());
    }
    let mut pairs = Vec::new();
    for component in raw.split('&') {
        if component.is_empty() {
            return None;
        }
        let (k, v) = component.split_once('=').unwrap_or((component, ""));
        let k = percent_decode(k)?;
        if k.is_empty() {
            return None;
        }
        pairs.push((k, percent_decode(v)?));
    }
    pairs.sort();
    Some(pairs)
}

pub(crate) fn encode_pairs(pairs: &[(Vec<u8>, Vec<u8>)]) -> String {
    let len = pairs.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
    let mut out = String::with_capacity(len);
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        percent_encode_into(&mut out, k);
        out.push('=');
        percent_encode_into(&mut out, v);
    }
    out
}

pub(crate) fn utf8_pairs(pairs: BytePairs) -> Option<Vec<(String, String)>> {
    pairs
        .into_iter()
        .map(|(k, v)| Some((String::from_utf8(k).ok()?, String::from_utf8(v).ok()?)))
        .collect()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests panic on a failed setup step")]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../testdata/scope-query.json");

    fn canonical_query(raw: &str) -> Option<String> {
        Some(encode_pairs(&decoded_pairs(raw)?))
    }

    #[test]
    fn shared_query_vectors() {
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        for case in v["query"].as_array().unwrap() {
            let raw = case["raw"].as_str().unwrap();
            let got = canonical_query(raw);
            match case.get("canonical").and_then(|c| c.as_str()) {
                Some(want) => assert_eq!(got.as_deref(), Some(want), "raw={raw}"),
                None => assert!(got.is_none(), "raw={raw} should fail, got {got:?}"),
            }
        }
    }

    #[test]
    fn canonical_is_idempotent() {
        let raw = "tag=b&tag=a&role=viewer%3aread";
        let once = canonical_query(raw).unwrap();
        assert_eq!(canonical_query(&once).unwrap(), once);
        assert_eq!(once, "role=viewer%3Aread&tag=a&tag=b");
    }

    #[test]
    fn plus_is_literal() {
        assert_eq!(
            utf8_pairs(decoded_pairs("a=b%2Bc").unwrap()).unwrap(),
            vec![("a".into(), "b+c".into())]
        );
    }
}
