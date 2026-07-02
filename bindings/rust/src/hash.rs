use std::fmt;

pub const BLAKE3_PREFIX: &str = "blake3:";
pub const CANON_VERSION: &str = "argus-jcs-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashBlob {
    pub content_hash: String,
    pub size_bytes: u64,
    pub canon_version: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashBlobError {
    SizeOverflow,
}

impl fmt::Display for HashBlobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashBlobError::SizeOverflow => formatter.write_str("hash input size exceeds u64"),
        }
    }
}

impl std::error::Error for HashBlobError {}

pub struct BlobHasher {
    hasher: blake3::Hasher,
    size_bytes: u64,
}

impl BlobHasher {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            size_bytes: 0,
        }
    }

    pub fn update(&mut self, chunk: &[u8]) -> Result<&mut Self, HashBlobError> {
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| HashBlobError::SizeOverflow)?;
        self.size_bytes = self
            .size_bytes
            .checked_add(chunk_len)
            .ok_or(HashBlobError::SizeOverflow)?;
        self.hasher.update(chunk);
        Ok(self)
    }

    pub fn finalize(self) -> HashBlob {
        HashBlob {
            content_hash: format!("{BLAKE3_PREFIX}{}", self.hasher.finalize().to_hex()),
            size_bytes: self.size_bytes,
            canon_version: CANON_VERSION,
        }
    }
}

impl Default for BlobHasher {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hash_bytes(payload: &[u8]) -> String {
    hash_blob(payload).content_hash
}

pub fn hash_blob(payload: &[u8]) -> HashBlob {
    let mut hasher = BlobHasher::new();
    hasher.update(payload).expect("slice length fits in u64");
    hasher.finalize()
}

pub fn hash_blob_stream<I, B>(chunks: I) -> Result<HashBlob, HashBlobError>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut hasher = BlobHasher::new();
    for chunk in chunks {
        hasher.update(chunk.as_ref())?;
    }
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blob_matches_known_blake3_vector() {
        let result = hash_blob(b"");

        assert_eq!(
            result.content_hash,
            "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(result.size_bytes, 0);
        assert_eq!(result.canon_version, CANON_VERSION);
    }

    #[test]
    fn streaming_chunks_match_single_pass_hash() {
        let chunks: Vec<&[u8]> = vec![&b"arg"[..], &b"us"[..], &b""[..], &b"-hash"[..]];
        let streaming = hash_blob_stream(chunks).expect("streaming hash succeeds");
        let single_pass = hash_blob(b"argus-hash");

        assert_eq!(streaming, single_pass);
        assert_eq!(streaming.size_bytes, 10);
    }

    #[test]
    fn streaming_large_chunk_sequence_matches_single_pass_hash() {
        let mut hasher = BlobHasher::new();
        let mut single_pass_payload = Vec::new();

        for index in 0..4096 {
            let chunk = vec![(index % 251) as u8; 257];
            hasher.update(&chunk).expect("streaming update succeeds");
            single_pass_payload.extend_from_slice(&chunk);
        }

        assert_eq!(hasher.finalize(), hash_blob(&single_pass_payload));
    }

    #[test]
    fn size_overflow_fails_before_hash_update() {
        let mut hasher = BlobHasher {
            hasher: blake3::Hasher::new(),
            size_bytes: u64::MAX,
        };

        match hasher.update(b"x") {
            Err(error) => assert_eq!(error, HashBlobError::SizeOverflow),
            Ok(_) => panic!("expected size overflow"),
        }
    }
}
