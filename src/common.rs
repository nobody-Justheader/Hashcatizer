/// Shared byte-parsing utilities used by every converter.

/// Encode bytes as lowercase hex string.
#[inline]
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode a hex string to bytes.
#[inline]
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| e.to_string())
}

/// Read a little-endian u16 from `data` at `offset`.
#[inline]
pub fn u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

/// Read a big-endian u16 from `data` at `offset`.
#[inline]
pub fn u16_be(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap())
}

/// Read a little-endian u32 from `data` at `offset`.
#[inline]
pub fn u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Read a big-endian u32 from `data` at `offset`.
#[inline]
pub fn u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Read a little-endian u64 from `data` at `offset`.
#[inline]
pub fn u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Read a little-endian i64 from `data` at `offset`.
#[inline]
pub fn i64_le(data: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Safe slice access — returns empty slice if out of bounds.
#[inline]
pub fn safe_slice(data: &[u8], start: usize, end: usize) -> &[u8] {
    let end = end.min(data.len());
    if start >= end { &[] } else { &data[start..end] }
}

/// Decode bytes as UTF-16-LE to String.
pub fn utf16le_decode(data: &[u8]) -> String {
    let words: Vec<u16> = data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    String::from_utf16_lossy(&words).trim_end_matches('\0').to_string()
}

/// Base64-decode a string (standard alphabet).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| e.to_string())
}

/// Base64-encode bytes (standard alphabet).
pub fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Read a 4-byte big-endian length-prefixed byte string.
pub fn read_be_blob<'a>(data: &'a [u8], offset: usize) -> Option<(&'a [u8], usize)> {
    if offset + 4 > data.len() {
        return None;
    }
    let len = u32_be(data, offset) as usize;
    let end = offset + 4 + len;
    if end > data.len() {
        return None;
    }
    Some((&data[offset + 4..end], end))
}

/// Bitcoin wallet compact-size integer.
pub fn read_compact_size(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() {
        return None;
    }
    match data[offset] {
        v if v < 0xfd => Some((v as u64, offset + 1)),
        0xfd => {
            if offset + 3 > data.len() { return None; }
            Some((u16_le(data, offset + 1) as u64, offset + 3))
        }
        0xfe => {
            if offset + 5 > data.len() { return None; }
            Some((u32_le(data, offset + 1) as u64, offset + 5))
        }
        _ => {
            if offset + 9 > data.len() { return None; }
            Some((u64_le(data, offset + 1), offset + 9))
        }
    }
}
