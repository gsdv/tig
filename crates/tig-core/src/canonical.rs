//! Deterministic CBOR encoding.
//!
//! Content addressing is only sound if every implementation that
//! encodes the same logical object produces the same bytes. ciborium
//! is *almost* canonical out of the box — definite-length items,
//! shortest integer / length encodings — but it emits struct fields
//! in source-code order, not in canonical map-key order. Two
//! implementations whose Rust struct field order happens to differ
//! would produce different bytes and therefore different hashes for
//! the same logical object.
//!
//! This module closes that gap. [`canonical_encode`] serializes a
//! value through ciborium's `Value` intermediate, sorts every map's
//! keys recursively per the RFC 8949 §4.2.1 "Core Deterministic
//! Encoding" rule (pure bytewise-lexicographic on the canonical
//! encoding of the key), then re-emits the value to bytes. Decoding
//! goes through plain ciborium since the wire format is just CBOR.
//!
//! Performance: one extra serialize → Value → serialize round-trip
//! per object. For our objects (kilobyte-scale at most) this is
//! microseconds — acceptable for content addressing.
//!
//! Why not switch to a different crate? `cbor4ii` and `minicbor` both
//! offer canonical modes. Wrapping ciborium keeps the dep tree
//! identical and the conversion contained to this one file. If we
//! ever measure that the round-trip is a bottleneck (it won't be at
//! current scale), swapping to a streaming canonical encoder is a
//! one-file change.

use ciborium::Value;
use std::cmp::Ordering;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encode to Value failed: {0}")]
    ValueEncode(String),
    #[error("encode Value to bytes failed: {0}")]
    ByteEncode(String),
}

/// Serialize `value` to CBOR bytes with map keys sorted per RFC 8949
/// §4.2.1. The output is *the* canonical representation: any other
/// canonical implementation receiving the same logical value will
/// produce byte-identical output.
pub fn canonical_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut v = Value::serialized(value).map_err(|e| Error::ValueEncode(e.to_string()))?;
    canonicalize(&mut v)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&v, &mut out).map_err(|e| Error::ByteEncode(e.to_string()))?;
    Ok(out)
}

/// Recursively walk `v`, sorting every map's entries in-place per the
/// canonical key order. Arrays preserve their original order
/// (sequence position carries meaning); only map keys get sorted.
fn canonicalize(v: &mut Value) -> Result<(), Error> {
    match v {
        Value::Map(entries) => {
            // Canonicalize children first so the keys we sort by are
            // themselves in canonical form. (For our schemas keys are
            // always small atoms, but the recursion is correct in
            // general.)
            for (k, val) in entries.iter_mut() {
                canonicalize(k)?;
                canonicalize(val)?;
            }
            // Compute each key's canonical-encoded bytes once and sort
            // by them. RFC 8949 §4.2.1: bytewise lexicographic on the
            // canonical encoding of the key. For our text-keyed
            // structs this collapses to "shorter keys first, then
            // alphabetical" since CBOR text strings encode length in
            // the leading byte.
            let mut indexed: Vec<(Vec<u8>, (Value, Value))> = Vec::with_capacity(entries.len());
            for (k, val) in entries.drain(..) {
                let mut kb = Vec::new();
                ciborium::ser::into_writer(&k, &mut kb)
                    .map_err(|e| Error::ByteEncode(e.to_string()))?;
                indexed.push((kb, (k, val)));
            }
            indexed.sort_by(|a, b| cmp_canonical(&a.0, &b.0));
            entries.extend(indexed.into_iter().map(|(_, kv)| kv));
        }
        Value::Array(elems) => {
            for e in elems.iter_mut() {
                canonicalize(e)?;
            }
        }
        // Tagged values can contain inner Values; recurse.
        Value::Tag(_, inner) => canonicalize(inner)?,
        // Scalars: nothing to do.
        _ => {}
    }
    Ok(())
}

/// RFC 8949 §4.2.1 "Core Deterministic Encoding": **bytewise**
/// lexicographic on the canonical encodings. (Not RFC 7049's older
/// length-first rule. For our text-string keys the practical
/// behavior is identical because CBOR encodes length in the leading
/// byte.)
fn cmp_canonical(a: &[u8], b: &[u8]) -> Ordering {
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Two structs with the same logical content but different field
    /// declaration orders must produce byte-identical canonical
    /// encodings. This is the core property we're buying.
    #[test]
    fn reordering_fields_does_not_change_output() {
        #[derive(Serialize)]
        struct OrderA {
            zeta: u32,
            alpha: u32,
            mu: u32,
        }
        #[derive(Serialize)]
        struct OrderB {
            mu: u32,
            zeta: u32,
            alpha: u32,
        }
        let a = canonical_encode(&OrderA {
            zeta: 3,
            alpha: 1,
            mu: 2,
        })
        .unwrap();
        let b = canonical_encode(&OrderB {
            mu: 2,
            zeta: 3,
            alpha: 1,
        })
        .unwrap();
        assert_eq!(a, b, "field order must not affect canonical encoding");
    }

    #[test]
    fn arrays_preserve_position() {
        // Array elements are semantically ordered; we must not
        // reorder them.
        let v = vec![
            "bravo".to_string(),
            "alpha".to_string(),
            "charlie".to_string(),
        ];
        let a = canonical_encode(&v).unwrap();
        let b = canonical_encode(&v).unwrap();
        assert_eq!(a, b);
        // Decode and compare order:
        let back: Vec<String> = ciborium::de::from_reader(a.as_slice()).unwrap();
        assert_eq!(back, vec!["bravo", "alpha", "charlie"]);
    }

    #[test]
    fn output_is_stable_for_identical_input() {
        #[derive(Serialize, Deserialize)]
        struct S {
            name: String,
            count: u32,
        }
        let s = S {
            name: "tig".into(),
            count: 7,
        };
        let a = canonical_encode(&s).unwrap();
        let b = canonical_encode(&s).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn nested_maps_also_get_canonicalized() {
        #[derive(Serialize)]
        struct Outer {
            inner: Inner,
        }
        #[derive(Serialize)]
        struct Inner {
            zeta: u32,
            alpha: u32,
        }
        let a = canonical_encode(&Outer {
            inner: Inner { zeta: 9, alpha: 1 },
        })
        .unwrap();
        let b = canonical_encode(&Outer {
            inner: Inner { zeta: 9, alpha: 1 },
        })
        .unwrap();
        assert_eq!(a, b);
        // Decode and inspect the order of the inner map's keys via
        // the Value layer.
        let v: Value = ciborium::de::from_reader(a.as_slice()).unwrap();
        if let Value::Map(outer_entries) = &v {
            // outer has one key "inner"; its value is a map.
            assert_eq!(outer_entries.len(), 1);
            if let Value::Map(inner_entries) = &outer_entries[0].1 {
                let keys: Vec<&str> = inner_entries
                    .iter()
                    .filter_map(|(k, _)| {
                        if let Value::Text(s) = k {
                            Some(s.as_str())
                        } else {
                            None
                        }
                    })
                    .collect();
                // For length-5 vs length-4 strings, "alpha" (5) and
                // "zeta" (4) → "zeta" sorts first because its first
                // CBOR byte (0x64) is less than "alpha"'s (0x65).
                assert_eq!(keys, vec!["zeta", "alpha"]);
            } else {
                panic!("inner not a map");
            }
        } else {
            panic!("outer not a map");
        }
    }

    /// Pin the exact output bytes for a small fixture. If a future
    /// change to canonicalize() ever silently breaks the wire format
    /// — e.g. someone reorders arrays accidentally — this test fails
    /// loudly. The hex literal is the canonical-CBOR encoding of
    /// `{count: 7, name: "tig"}` in name-then-count map order (length
    /// 4 < 5, then bytewise on bytes 0x6364 → count vs 0x656e → name;
    /// but actually the CBOR keys "count" and "name" both have
    /// length 5 and 4 respectively, so we expect name then count).
    #[test]
    fn fixture_byte_sequence_is_stable() {
        #[derive(Serialize)]
        struct S {
            count: u32,
            name: String,
        }
        let bytes = canonical_encode(&S {
            count: 7,
            name: "tig".into(),
        })
        .unwrap();
        // Expected encoding (canonical order: "name" before "count"
        // because 0x64 < 0x65 in the leading-byte comparison):
        //   A2                         ; map(2)
        //     64 6E 61 6D 65           ; tstr(4) "name"
        //     63 74 69 67              ; tstr(3) "tig"
        //     65 63 6F 75 6E 74        ; tstr(5) "count"
        //     07                       ; uint(7)
        let expected = hex::decode("a2646e616d656374696765636f756e7407").unwrap();
        assert_eq!(
            bytes, expected,
            "canonical encoding drifted; hash stability is broken across versions"
        );
    }
}
