use cborrs_nondet::cbornondet::*;

/// An owned CBOR value supporting arbitrary nesting.
///
/// Covers the major CBOR types: integers, simple values, byte/text strings,
/// arrays, maps, and tagged values. Unlike [`CborNondet`], this type owns
/// all its data and can be freely stored, cloned, and nested.
#[derive(Clone, PartialEq)]
pub enum CborValue {
    Int(i64),
    Simple(u8),
    ByteString(Vec<u8>),
    TextString(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Tagged {
        tag: u64,
        payload: Box<CborValue>,
    },
}

impl CborValue {
    /// Parse CBOR bytes into an owned `CborValue`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (item, _) = cbor_nondet_parse(None, false, bytes)
            .ok_or("Failed to parse CBOR bytes")?;
        Self::from_raw(item)
    }

    /// Serialize this value to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            CborValue::Int(v) => {
                let (kind, raw) = Self::i64_to_cbor_int(*v);
                serialize(cbor_nondet_mk_int64(kind, raw))
            }
            CborValue::Simple(v) => {
                let item = cbor_nondet_mk_simple_value(*v)
                    .ok_or("Failed to make CBOR simple value")?;
                serialize(item)
            }
            CborValue::ByteString(b) => {
                let item = cbor_nondet_mk_byte_string(b)
                    .ok_or("Failed to make CBOR byte string")?;
                serialize(item)
            }
            CborValue::TextString(s) => {
                let item = cbor_nondet_mk_text_string(s)
                    .ok_or("Failed to make CBOR text string")?;
                serialize(item)
            }
            CborValue::Array(items) => {
                let child_bytes: Vec<Vec<u8>> = items
                    .iter()
                    .map(|v| v.to_bytes())
                    .collect::<Result<_, _>>()?;

                let mut parsed = Vec::with_capacity(child_bytes.len());
                for bytes in &child_bytes {
                    let (item, _) = cbor_nondet_parse(None, false, bytes)
                        .ok_or("Failed to re-parse child CBOR")?;
                    parsed.push(item);
                }

                let arr = cbor_nondet_mk_array(&parsed)
                    .ok_or("Failed to build CBOR array")?;
                serialize(arr)
            }
            CborValue::Map(entries) => {
                let child_bytes: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| Ok((k.to_bytes()?, v.to_bytes()?)))
                    .collect::<Result<_, String>>()?;

                let mut parsed_entries = Vec::with_capacity(child_bytes.len());
                for (kb, vb) in &child_bytes {
                    let (k, _) = cbor_nondet_parse(None, false, kb)
                        .ok_or("Failed to re-parse map key")?;
                    let (v, _) = cbor_nondet_parse(None, false, vb)
                        .ok_or("Failed to re-parse map value")?;
                    parsed_entries.push(cbor_nondet_mk_map_entry(k, v));
                }

                let map = cbor_nondet_mk_map(&mut parsed_entries)
                    .ok_or("Failed to build CBOR map")?;
                serialize(map)
            }
            CborValue::Tagged { tag, payload } => {
                let payload_bytes = payload.to_bytes()?;
                let (inner, _) = cbor_nondet_parse(None, false, &payload_bytes)
                    .ok_or("Failed to re-parse tagged payload")?;
                let tagged = cbor_nondet_mk_tagged(*tag, &inner);
                serialize(tagged)
            }
        }
    }

    /// Get array element by index. Returns an error if not an array.
    pub fn array_at(&self, index: usize) -> Result<&CborValue, String> {
        match self {
            CborValue::Array(items) => items
                .get(index)
                .ok_or_else(|| format!("Index {index} out of bounds")),
            other => Err(format!("Expected Array, got {:?}", other.type_name())),
        }
    }

    /// Look up a map value by integer key. Returns an error if not a map.
    pub fn map_at_int(&self, key: i64) -> Result<&CborValue, String> {
        let target = CborValue::Int(key);
        self.map_at(&target)
    }

    /// Look up a map value by text string key. Returns an error if not a map.
    pub fn map_at_str(&self, key: &str) -> Result<&CborValue, String> {
        let target = CborValue::TextString(key.to_string());
        self.map_at(&target)
    }

    /// Look up a map value by a CborValue key (must be Int or TextString).
    /// Returns an error if not a map or if the key type is invalid.
    pub fn map_at(&self, key: &CborValue) -> Result<&CborValue, String> {
        match key {
            CborValue::Int(_) | CborValue::TextString(_) => {}
            _ => return Err("Map keys can only be Int or TextString".into()),
        }
        match self {
            CborValue::Map(entries) => entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .ok_or_else(|| format!("Key {:?} not found in map", key)),
            other => Err(format!("Expected Map, got {:?}", other.type_name())),
        }
    }

    /// Iterate over array elements. Returns an error if not an array.
    pub fn iter_array(&self) -> Result<std::slice::Iter<'_, CborValue>, String> {
        match self {
            CborValue::Array(items) => Ok(items.iter()),
            other => Err(format!("Expected Array, got {:?}", other.type_name())),
        }
    }

    /// Iterate over map entries as `(key, value)` pairs.
    /// Returns an error if not a map.
    pub fn iter_map(
        &self,
    ) -> Result<impl Iterator<Item = (&CborValue, &CborValue)>, String> {
        match self {
            CborValue::Map(entries) => {
                Ok(entries.iter().map(|(k, v)| (k, v)))
            }
            other => Err(format!("Expected Map, got {:?}", other.type_name())),
        }
    }

    /// Number of elements in an array or map.
    /// Returns an error for other types.
    pub fn len(&self) -> Result<usize, String> {
        match self {
            CborValue::Array(items) => Ok(items.len()),
            CborValue::Map(entries) => Ok(entries.len()),
            other => Err(format!(
                "len() not applicable to {:?}",
                other.type_name()
            )),
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            CborValue::Int(_) => "Int",
            CborValue::Simple(_) => "Simple",
            CborValue::ByteString(_) => "ByteString",
            CborValue::TextString(_) => "TextString",
            CborValue::Array(_) => "Array",
            CborValue::Map(_) => "Map",
            CborValue::Tagged { .. } => "Tagged",
        }
    }

    fn i64_to_cbor_int(v: i64) -> (CborNondetIntKind, u64) {
        if v >= 0 {
            (CborNondetIntKind::UInt64, v as u64)
        } else {
            // CBOR encodes negative n as -(1 + encoded), so encoded = -n - 1.
            // Use wrapping arithmetic to handle i64::MIN without overflow.
            (CborNondetIntKind::NegInt64, (v as u64).wrapping_neg() - 1)
        }
    }

    fn cbor_int_to_i64(
        kind: CborNondetIntKind,
        value: u64,
    ) -> Result<i64, String> {
        match kind {
            CborNondetIntKind::UInt64 => i64::try_from(value)
                .map_err(|_| format!("CBOR uint {value} exceeds i64 range")),
            CborNondetIntKind::NegInt64 => {
                // CBOR negative: actual = -(value + 1)
                // Compute as u64 first then reinterpret, to avoid overflow.
                let neg_val = (!value) as i64; // bitwise NOT gives -(value+1) in two's complement
                if value > (i64::MAX as u64) {
                    return Err(format!(
                        "CBOR nint exceeds i64 range"
                    ));
                }
                Ok(neg_val)
            }
        }
    }

    fn from_raw(item: CborNondet) -> Result<Self, String> {
        match cbor_nondet_destruct(item) {
            CborNondetView::Int64 { kind, value } => {
                Ok(CborValue::Int(Self::cbor_int_to_i64(kind, value)?))
            }
            CborNondetView::SimpleValue { _0: v } => Ok(CborValue::Simple(v)),
            CborNondetView::ByteString { payload } => {
                Ok(CborValue::ByteString(payload.to_vec()))
            }
            CborNondetView::TextString { payload } => {
                Ok(CborValue::TextString(payload.to_string()))
            }
            CborNondetView::Array { _0: arr } => {
                let len = cbor_nondet_get_array_length(arr);
                let mut items = Vec::with_capacity(len as usize);
                for i in 0..len {
                    let child = cbor_nondet_get_array_item(arr, i)
                        .ok_or("Failed to get array item")?;
                    items.push(Self::from_raw(child)?);
                }
                Ok(CborValue::Array(items))
            }
            CborNondetView::Map { _0: map } => {
                let mut entries = Vec::with_capacity(
                    cbor_nondet_get_map_length(map) as usize,
                );
                for entry in map {
                    let k = Self::from_raw(
                        cbor_nondet_map_entry_key(entry),
                    )?;
                    let v = Self::from_raw(
                        cbor_nondet_map_entry_value(entry),
                    )?;
                    entries.push((k, v));
                }
                Ok(CborValue::Map(entries))
            }
            CborNondetView::Tagged { tag, payload } => {
                let inner = Self::from_raw(payload)?;
                Ok(CborValue::Tagged {
                    tag,
                    payload: Box::new(inner),
                })
            }
        }
    }
}

fn serialize(item: CborNondet) -> Result<Vec<u8>, String> {
    let sz = cbor_nondet_size(item, usize::MAX)
        .ok_or("Failed to estimate CBOR serialization size")?;
    let mut buf = vec![0u8; sz];
    let written = cbor_nondet_serialize(item, &mut buf)
        .ok_or("Failed to serialize CBOR")?;
    if sz != written {
        return Err(format!(
            "CBOR serialize mismatch: written {written} != expected {sz}"
        ));
    }
    Ok(buf)
}

impl std::fmt::Debug for CborValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CborValue::Int(v) => write!(f, "Int({})", v),
            CborValue::Simple(v) => write!(f, "Simple({})", v),
            CborValue::ByteString(b) => write!(f, "Bstr({} bytes)", b.len()),
            CborValue::TextString(s) => write!(f, "Tstr({:?})", s),
            CborValue::Array(items) => f.debug_list().entries(items).finish(),
            CborValue::Map(entries) => f
                .debug_map()
                .entries(entries.iter().map(|(k, v)| (k, v)))
                .finish(),
            CborValue::Tagged { tag, payload } => {
                write!(f, "Tag({}, {:?})", tag, payload)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(val: &CborValue) {
        let bytes = val.to_bytes().unwrap();
        let parsed = CborValue::from_bytes(&bytes).unwrap();
        assert_eq!(val, &parsed);
    }

    // --- Int ---

    #[test]
    fn round_trip_uint() {
        round_trip(&CborValue::Int(42));
    }

    #[test]
    fn round_trip_nint() {
        round_trip(&CborValue::Int(-7));
    }

    #[test]
    fn round_trip_zero() {
        round_trip(&CborValue::Int(0));
    }

    #[test]
    fn round_trip_i64_min() {
        round_trip(&CborValue::Int(i64::MIN));
    }

    // --- Simple ---

    #[test]
    fn round_trip_simple_true() {
        round_trip(&CborValue::Simple(21)); // CBOR true
    }

    #[test]
    fn round_trip_simple_null() {
        round_trip(&CborValue::Simple(22)); // CBOR null
    }

    // --- ByteString ---

    #[test]
    fn round_trip_bstr() {
        round_trip(&CborValue::ByteString(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn round_trip_bstr_empty() {
        round_trip(&CborValue::ByteString(vec![]));
    }

    // --- TextString ---

    #[test]
    fn round_trip_tstr() {
        round_trip(&CborValue::TextString("hello world".into()));
    }

    #[test]
    fn round_trip_tstr_empty() {
        round_trip(&CborValue::TextString(String::new()));
    }

    // --- Array ---

    #[test]
    fn round_trip_flat_array() {
        round_trip(&CborValue::Array(vec![
            CborValue::Int(1),
            CborValue::Int(2),
            CborValue::Int(3),
        ]));
    }

    #[test]
    fn round_trip_nested_array() {
        round_trip(&CborValue::Array(vec![
            CborValue::Int(1),
            CborValue::Array(vec![
                CborValue::Int(-1),
                CborValue::Array(vec![CborValue::Int(99)]),
            ]),
            CborValue::Int(3),
        ]));
    }

    #[test]
    fn round_trip_empty_array() {
        round_trip(&CborValue::Array(vec![]));
    }

    // --- Map ---

    #[test]
    fn round_trip_map_int_keys() {
        round_trip(&CborValue::Map(vec![
            (CborValue::Int(1), CborValue::TextString("one".into())),
            (CborValue::Int(2), CborValue::TextString("two".into())),
        ]));
    }

    #[test]
    fn round_trip_map_str_keys() {
        round_trip(&CborValue::Map(vec![
            (
                CborValue::TextString("name".into()),
                CborValue::TextString("alice".into()),
            ),
            (CborValue::TextString("age".into()), CborValue::Int(30)),
        ]));
    }

    #[test]
    fn round_trip_map_nested_value() {
        round_trip(&CborValue::Map(vec![(
            CborValue::Int(1),
            CborValue::Array(vec![
                CborValue::ByteString(vec![1, 2]),
                CborValue::Simple(22),
            ]),
        )]));
    }

    #[test]
    fn round_trip_empty_map() {
        round_trip(&CborValue::Map(vec![]));
    }

    // --- Tagged ---

    #[test]
    fn round_trip_tagged() {
        round_trip(&CborValue::Tagged {
            tag: 18,
            payload: Box::new(CborValue::ByteString(b"payload".to_vec())),
        });
    }

    #[test]
    fn round_trip_tagged_nested() {
        round_trip(&CborValue::Tagged {
            tag: 1,
            payload: Box::new(CborValue::Array(vec![
                CborValue::Int(42),
                CborValue::TextString("inside tag".into()),
            ])),
        });
    }

    // --- Mixed nesting ---

    #[test]
    fn round_trip_complex() {
        round_trip(&CborValue::Array(vec![
            CborValue::ByteString(vec![0xFF]),
            CborValue::Map(vec![
                (
                    CborValue::Int(1),
                    CborValue::Tagged {
                        tag: 99,
                        payload: Box::new(CborValue::TextString(
                            "nested".into(),
                        )),
                    },
                ),
                (
                    CborValue::Int(2),
                    CborValue::Array(vec![CborValue::Simple(22)]),
                ),
            ]),
            CborValue::Int(-100),
        ]));
    }

    // --- Accessor: get (array index) ---

    #[test]
    fn array_at_item() {
        let arr = CborValue::Array(vec![
            CborValue::Int(10),
            CborValue::Int(20),
        ]);
        assert_eq!(arr.array_at(0).unwrap(), &CborValue::Int(10));
        assert_eq!(arr.array_at(1).unwrap(), &CborValue::Int(20));
        assert!(arr.array_at(2).is_err());
    }

    #[test]
    fn array_at_on_non_array_is_err() {
        assert!(CborValue::Int(1).array_at(0).is_err());
        assert!(CborValue::TextString("hi".into()).array_at(0).is_err());
        assert!(CborValue::Map(vec![]).array_at(0).is_err());
    }

    // --- Accessor: map lookup ---

    #[test]
    fn map_at_int_key() {
        let map = CborValue::Map(vec![
            (CborValue::Int(1), CborValue::TextString("one".into())),
            (CborValue::Int(2), CborValue::TextString("two".into())),
        ]);
        assert_eq!(
            map.map_at_int(1).unwrap(),
            &CborValue::TextString("one".into())
        );
        assert_eq!(
            map.map_at_int(2).unwrap(),
            &CborValue::TextString("two".into())
        );
        assert!(map.map_at_int(3).is_err());
    }

    #[test]
    fn map_at_str_key() {
        let map = CborValue::Map(vec![(
            CborValue::TextString("key".into()),
            CborValue::Int(42),
        )]);
        assert_eq!(map.map_at_str("key").unwrap(), &CborValue::Int(42));
        assert!(map.map_at_str("missing").is_err());
    }

    #[test]
    fn map_at_invalid_key_type() {
        let map = CborValue::Map(vec![]);
        let bad_key = CborValue::ByteString(vec![]);
        assert!(map.map_at(&bad_key).is_err());
    }

    #[test]
    fn map_at_on_non_map_is_err() {
        assert!(CborValue::Int(1).map_at_int(0).is_err());
        assert!(CborValue::Array(vec![]).map_at_str("x").is_err());
    }

    // --- Iterators ---

    #[test]
    fn iter_array_elements() {
        let arr = CborValue::Array(vec![
            CborValue::Int(1),
            CborValue::Int(2),
            CborValue::Int(3),
        ]);
        let collected: Vec<_> = arr.iter_array().unwrap().collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0], &CborValue::Int(1));
    }

    #[test]
    fn iter_array_on_non_array_is_err() {
        assert!(CborValue::Int(1).iter_array().is_err());
    }

    #[test]
    fn iter_map_entries() {
        let map = CborValue::Map(vec![
            (CborValue::Int(1), CborValue::TextString("a".into())),
            (CborValue::Int(2), CborValue::TextString("b".into())),
        ]);
        let collected: Vec<_> = map.iter_map().unwrap().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].0, &CborValue::Int(1));
    }

    #[test]
    fn iter_map_on_non_map_is_err() {
        assert!(CborValue::Array(vec![]).iter_map().is_err());
    }

    // --- len ---

    #[test]
    fn len_array() {
        let arr = CborValue::Array(vec![CborValue::Int(1)]);
        assert_eq!(arr.len().unwrap(), 1);
    }

    #[test]
    fn len_map() {
        let map = CborValue::Map(vec![
            (CborValue::Int(1), CborValue::Int(2)),
        ]);
        assert_eq!(map.len().unwrap(), 1);
    }

    #[test]
    fn len_on_other_types_is_err() {
        assert!(CborValue::Int(0).len().is_err());
        assert!(CborValue::TextString("x".into()).len().is_err());
    }

    // --- Debug ---

    #[test]
    fn debug_format() {
        let val = CborValue::Array(vec![
            CborValue::Int(42),
            CborValue::Int(-7),
        ]);
        let s = format!("{:?}", val);
        assert!(s.contains("Int(42)"));
        assert!(s.contains("Int(-7)"));
    }
}
