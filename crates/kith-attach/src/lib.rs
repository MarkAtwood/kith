use std::io;
use std::path::PathBuf;

use rand::Rng;
use sha2::{Digest, Sha256};

/// Hard upper bound on blob size accepted by [`BlobStore::write_blob`].
/// `write_blob_streaming` uses its caller-supplied `max_bytes` parameter
/// instead (which must be ≤ this limit in practice).
const MAX_BLOB_BYTES: u64 = 200 * 1024 * 1024; // 200 MiB

/// On-disk blob storage for kith attachments.
pub struct BlobStore {
    base_dir: PathBuf,
}

impl BlobStore {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        BlobStore {
            base_dir: base_dir.into(),
        }
    }

    pub fn init(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.base_dir)
    }

    pub fn generate_blob_id() -> String {
        let bytes: [u8; 32] = rand::rng().random();
        hex_encode(&bytes)
    }

    pub fn validate_blob_id(id: &str) -> Result<(), String> {
        if id.is_empty() {
            return Err("blob_id must not be empty".into());
        }
        if id.len() > 128 {
            return Err(format!(
                "blob_id length {} exceeds maximum of 128",
                id.len()
            ));
        }
        if id.starts_with('.') {
            return Err("blob_id must not start with '.'".into());
        }
        for ch in id.chars() {
            if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-') {
                return Err(format!("blob_id contains disallowed character: {:?}", ch));
            }
        }
        Ok(())
    }

    pub fn blob_path(&self, id: &str) -> PathBuf {
        // Validate in all build configurations, not just debug.  Every public
        // method in BlobStore calls validate_blob_id() before calling this, so
        // this fires only if a caller bypasses that contract.  The validation
        // ensures id is lowercase hex only (no '/', no '..') so base_dir.join(id)
        // cannot traverse outside base_dir — but we make that invariant explicit
        // here as a defence-in-depth safety net for future callers.
        assert!(
            Self::validate_blob_id(id).is_ok(),
            "BlobStore::blob_path called with invalid id: {id:?} — call validate_blob_id first"
        );
        self.base_dir.join(id)
    }

    /// Return `true` if the blob file exists on disk.
    ///
    /// Returns `false` for any `id` that fails [`validate_blob_id`] rather than
    /// panicking — a malformed id cannot refer to any valid blob.
    pub fn blob_exists(&self, id: &str) -> bool {
        if Self::validate_blob_id(id).is_err() {
            return false;
        }
        self.blob_path(id).exists()
    }

    pub async fn write_blob(&self, id: &str, data: &[u8]) -> Result<u64, io::Error> {
        Self::validate_blob_id(id)
            .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;

        if !self.base_dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "BlobStore base_dir does not exist: {:?}; was init() called?",
                    self.base_dir
                ),
            ));
        }

        if data.len() as u64 > MAX_BLOB_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "blob size {} exceeds hard limit of {} bytes",
                    data.len(),
                    MAX_BLOB_BYTES
                ),
            ));
        }

        let final_path = self.blob_path(id);
        // Unique nonce per write so concurrent writes for the same blob_id don't
        // share a temp path and corrupt each other.
        let nonce: u32 = rand::rng().random();
        let tmp_path = self.base_dir.join(format!("{id}.{nonce:08x}.tmp"));

        // Use mode 0o600 so the tmp file is only readable by the daemon process,
        // not world-readable via the process umask.  Mirrors the pattern in
        // kithctl/src/backup.rs.
        #[cfg(unix)]
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .await?;
        #[cfg(not(unix))]
        let mut file = tokio::fs::File::create(&tmp_path).await?;

        // Clean up the temp file if write or sync fails (don't leave orphaned .tmp files).
        if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, data).await {
            drop(file);
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }
        if let Err(e) = file.sync_all().await {
            drop(file);
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }
        drop(file);

        // Clean up the temp file if rename fails (cross-device move, permissions
        // error, etc.) so orphaned .tmp files do not accumulate in the blob dir.
        if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }
        Ok(data.len() as u64)
    }

    /// Stream an HTTP body to disk while hashing and enforcing a size limit.
    ///
    /// Chunks from `body` are fed to an incremental SHA-256 hasher and written
    /// to a temp file; on success the temp file is fsync'd and renamed to the
    /// final path atomically.  No heap buffer for the full payload is needed.
    ///
    /// Returns `(bytes_written, sha256_hex)` on success.
    /// Returns `Err` with `ErrorKind::InvalidInput` if `max_bytes` is exceeded.
    pub async fn write_blob_streaming(
        &self,
        id: &str,
        body: axum::body::Body,
        max_bytes: u64,
    ) -> Result<(u64, String), io::Error> {
        use http_body_util::BodyExt as _;
        use tokio::io::AsyncWriteExt as _;

        Self::validate_blob_id(id)
            .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;

        if max_bytes > MAX_BLOB_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("max_bytes {max_bytes} exceeds hard limit {MAX_BLOB_BYTES}"),
            ));
        }

        if !self.base_dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "BlobStore base_dir does not exist: {:?}; was init() called?",
                    self.base_dir
                ),
            ));
        }

        let final_path = self.blob_path(id);
        // Unique nonce per write so concurrent writes for the same blob_id don't
        // share a temp path and corrupt each other.
        let nonce: u32 = rand::rng().random();
        let tmp_path = self.base_dir.join(format!("{id}.{nonce:08x}.tmp"));

        // Use mode 0o600 so the tmp file is only readable by the daemon process.
        #[cfg(unix)]
        let mut tmp_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .await?;
        #[cfg(not(unix))]
        let mut tmp_file = tokio::fs::File::create(&tmp_path).await?;
        let mut hasher = Sha256::new();
        let mut total_bytes: u64 = 0;
        let mut body = body;

        loop {
            match body.frame().await {
                None => break,
                Some(Err(e)) => {
                    drop(tmp_file);
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return Err(io::Error::other(format!("body read error: {e}")));
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        total_bytes += data.len() as u64;
                        if total_bytes > max_bytes {
                            drop(tmp_file);
                            let _ = tokio::fs::remove_file(&tmp_path).await;
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "body exceeds max_bytes limit",
                            ));
                        }
                        hasher.update(&data);
                        if let Err(e) = tmp_file.write_all(&data).await {
                            drop(tmp_file);
                            let _ = tokio::fs::remove_file(&tmp_path).await;
                            return Err(e);
                        }
                    }
                }
            }
        }

        if let Err(e) = tmp_file.sync_all().await {
            drop(tmp_file);
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }
        drop(tmp_file);

        // Clean up the temp file if rename fails so orphaned .tmp files do not
        // accumulate in the blob dir.
        if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }

        let sha256 = format!("{:x}", hasher.finalize());
        Ok((total_bytes, sha256))
    }

    pub async fn read_blob(&self, id: &str) -> Result<Option<Vec<u8>>, io::Error> {
        Self::validate_blob_id(id)
            .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;

        let path = self.blob_path(id);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn delete_blob(&self, id: &str) -> Result<(), io::Error> {
        Self::validate_blob_id(id)
            .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;

        let path = self.blob_path(id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_empty_is_err() {
        assert!(BlobStore::validate_blob_id("").is_err());
    }
    #[test]
    fn validate_slash_is_err() {
        assert!(BlobStore::validate_blob_id("abc/def").is_err());
    }
    #[test]
    fn validate_dotdot_is_err() {
        assert!(BlobStore::validate_blob_id("..").is_err());
    }
    #[test]
    fn validate_leading_dot_is_err() {
        assert!(BlobStore::validate_blob_id(".hidden").is_err());
    }
    #[test]
    fn validate_null_byte_is_err() {
        assert!(BlobStore::validate_blob_id("abc\x00def").is_err());
    }
    #[test]
    fn validate_space_is_err() {
        assert!(BlobStore::validate_blob_id("abc def").is_err());
    }
    #[test]
    fn validate_too_long_is_err() {
        assert!(BlobStore::validate_blob_id(&"a".repeat(129)).is_err());
    }
    #[test]
    fn validate_64_char_hex_is_ok() {
        assert!(BlobStore::validate_blob_id(&"a".repeat(64)).is_ok());
    }
    #[test]
    fn validate_ulid_is_ok() {
        assert!(BlobStore::validate_blob_id("01ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());
    }
    #[test]
    fn validate_mixed_case_alphanum_underscore_dash_is_ok() {
        assert!(BlobStore::validate_blob_id("Blob_ID-42").is_ok());
    }
    #[test]
    fn generate_blob_id_is_64_char_lowercase_hex() {
        let id = BlobStore::generate_blob_id();
        assert_eq!(id.len(), 64);
        for ch in id.chars() {
            assert!(matches!(ch, '0'..='9' | 'a'..='f'));
        }
    }
    #[test]
    fn generate_blob_id_passes_validate() {
        assert!(BlobStore::validate_blob_id(&BlobStore::generate_blob_id()).is_ok());
    }

    fn make_temp_store() -> (BlobStore, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("TempDir::new should succeed");
        let store = BlobStore::new(dir.path());
        store.init().expect("init should create temp dir");
        (store, dir)
    }

    #[tokio::test]
    async fn write_read_roundtrip() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        let data: &[u8] = b"hello world";
        let written = store
            .write_blob(&id, data)
            .await
            .expect("write_blob failed");
        assert_eq!(written, data.len() as u64);
        let read_back = store
            .read_blob(&id)
            .await
            .expect("read_blob failed")
            .expect("expected Some");
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn write_overwrite_roundtrip() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        store
            .write_blob(&id, b"first")
            .await
            .expect("first write failed");
        store
            .write_blob(&id, b"second")
            .await
            .expect("second write failed");
        let read_back = store
            .read_blob(&id)
            .await
            .expect("read_blob failed")
            .expect("expected Some");
        assert_eq!(read_back, b"second");
    }

    #[tokio::test]
    async fn delete_makes_read_return_none() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        store
            .write_blob(&id, b"to be deleted")
            .await
            .expect("write_blob failed");
        store.delete_blob(&id).await.expect("delete_blob failed");
        assert!(store
            .read_blob(&id)
            .await
            .expect("read_blob failed")
            .is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_is_ok() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        store
            .delete_blob(&id)
            .await
            .expect("delete of nonexistent should be Ok");
    }

    #[tokio::test]
    async fn read_nonexistent_returns_none() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        assert!(store
            .read_blob(&id)
            .await
            .expect("read_blob failed")
            .is_none());
    }

    #[tokio::test]
    async fn write_empty_bytes_roundtrip() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        let written = store.write_blob(&id, b"").await.expect("write_blob failed");
        assert_eq!(written, 0);
        assert!(store
            .read_blob(&id)
            .await
            .expect("read_blob failed")
            .expect("expected Some")
            .is_empty());
    }

    #[tokio::test]
    async fn write_invalid_id_returns_error() {
        let (store, _dir) = make_temp_store();
        let result = store.write_blob("../escape", b"bad").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn read_invalid_id_returns_error() {
        let (store, _dir) = make_temp_store();
        let result = store.read_blob("").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn delete_invalid_id_returns_error() {
        let (store, _dir) = make_temp_store();
        let result = store.delete_blob("/absolute/path").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn write_streaming_roundtrip() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        let data = b"streaming hello world";
        let body = axum::body::Body::from(data.as_slice());
        let (bytes_written, sha256) = store
            .write_blob_streaming(&id, body, 1024)
            .await
            .expect("write_blob_streaming failed");
        assert_eq!(bytes_written, data.len() as u64);
        // Independent oracle: SHA-256 of known input.
        let mut h = Sha256::new();
        h.update(data);
        let expected = format!("{:x}", h.finalize());
        assert_eq!(sha256, expected);
        // Verify bytes were actually written to disk.
        let read_back = store
            .read_blob(&id)
            .await
            .expect("read_blob failed")
            .expect("expected Some");
        assert_eq!(read_back.as_slice(), data.as_slice());
    }

    #[tokio::test]
    async fn write_streaming_exceeds_limit_returns_err() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        let data = b"0123456789";
        let body = axum::body::Body::from(data.as_slice());
        let result = store.write_blob_streaming(&id, body, 5).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        // Temp file must be cleaned up.
        assert!(store.read_blob(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn write_streaming_invalid_id_returns_err() {
        let (store, _dir) = make_temp_store();
        let body = axum::body::Body::from(b"data".as_slice());
        let result = store.write_blob_streaming("../bad", body, 1024).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    // Oracle: MAX_BLOB_BYTES is a compile-time constant (200 MiB).  Passing a
    // slice whose length exceeds that constant must return Err(InvalidInput)
    // before any file I/O occurs.  The allocation is immediately freed on drop.
    #[tokio::test]
    async fn write_blob_oversized_returns_invalid_input() {
        let (store, _dir) = make_temp_store();
        let id = BlobStore::generate_blob_id();
        // Allocate exactly one byte over the hard cap.
        let data = vec![0u8; MAX_BLOB_BYTES as usize + 1];
        let result = store.write_blob(&id, &data).await;
        assert!(
            result.is_err(),
            "write_blob must reject data exceeding MAX_BLOB_BYTES"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "error kind must be InvalidInput for oversized blob"
        );
        // No file must have been created.
        assert!(
            store.read_blob(&id).await.unwrap().is_none(),
            "no blob file must exist after oversized write is rejected"
        );
    }

    // Oracle: write_blob on a BlobStore whose base_dir was never created (or was
    // dropped) must return Err(NotFound) rather than panicking or creating the
    // directory implicitly.  The error tells the caller that init() was not called.
    #[tokio::test]
    async fn write_blob_without_init_returns_not_found() {
        // Use a path guaranteed not to exist: a TempDir that has already been dropped.
        let nonexistent = {
            let dir = tempfile::TempDir::new().expect("TempDir::new should succeed");
            dir.path().to_path_buf()
            // dir dropped here — the directory is deleted
        };
        assert!(
            !nonexistent.exists(),
            "precondition: path must not exist after TempDir drop"
        );

        let store = BlobStore::new(&nonexistent);
        // Deliberately skip store.init() — this is exactly the scenario under test.

        let id = BlobStore::generate_blob_id();
        let result = store.write_blob(&id, b"payload").await;

        assert!(
            result.is_err(),
            "write_blob without init() must return Err; got Ok"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "error kind must be NotFound (base_dir missing)"
        );
    }
}
