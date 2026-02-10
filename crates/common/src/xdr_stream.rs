//! XDR output stream writer for size-prefixed binary frames.
//!
//! Implements the same wire format as stellar-core's `XDROutputFileStream`,
//! enabling binary-compatible metadata streaming to downstream consumers
//! (Horizon, ingestion pipelines).
//!
//! # Wire Format
//!
//! Each frame is written as:
//! ```text
//! [4-byte big-endian size with continuation bit] [XDR payload]
//! ```
//!
//! The size header has bit 31 set (the "continuation bit"), matching the
//! XDR record marking standard (RFC 1832 / RFC 4506).

use std::io::{self, BufWriter, Write};

use stellar_xdr::curr::WriteXdr;

/// An output stream that writes XDR values with size-prefix framing.
///
/// Each value is serialized to XDR, then written as a 4-byte big-endian
/// size header (with bit 31 set) followed by the XDR payload bytes.
/// This matches the wire format produced by stellar-core's
/// `XDROutputFileStream::writeOne`.
pub struct XdrOutputStream {
    writer: BufWriter<Box<dyn Write + Send>>,
}

impl XdrOutputStream {
    /// Open an XDR output stream writing to a file path.
    ///
    /// The path can be a regular file or a named pipe (FIFO).
    pub fn open(path: &str) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            writer: BufWriter::new(Box::new(file)),
        })
    }

    /// Create an XDR output stream from a raw file descriptor.
    ///
    /// # Safety
    ///
    /// The caller must ensure the file descriptor is valid and open for writing.
    /// This function takes ownership of the file descriptor.
    #[cfg(unix)]
    pub fn from_fd(fd: std::os::unix::io::RawFd) -> io::Result<Self> {
        use std::os::unix::io::FromRawFd;
        // SAFETY: caller guarantees the fd is valid and open for writing
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(Self {
            writer: BufWriter::new(Box::new(file)),
        })
    }

    /// Create an XDR output stream from any writer.
    ///
    /// Useful for testing with in-memory buffers.
    pub fn from_writer(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer: BufWriter::new(writer),
        }
    }

    /// Serialize a value to XDR and write it as a size-prefixed frame.
    ///
    /// Returns the total number of bytes written (4-byte header + payload).
    ///
    /// # Wire Format
    ///
    /// ```text
    /// byte[0] = ((sz >> 24) & 0xFF) | 0x80   // continuation bit set
    /// byte[1] = (sz >> 16) & 0xFF
    /// byte[2] = (sz >> 8) & 0xFF
    /// byte[3] = sz & 0xFF
    /// byte[4..4+sz] = XDR payload
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the serialized XDR payload is >= 0x80000000 bytes (2 GiB),
    /// matching stellar-core's `releaseAssertOrThrow`.
    pub fn write_one<T: WriteXdr>(&mut self, value: &T) -> io::Result<usize> {
        let payload = value
            .to_xdr(stellar_xdr::curr::Limits::none())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let sz = payload.len() as u32;
        assert!(
            sz < 0x8000_0000,
            "XDR payload size {} exceeds maximum (0x80000000)",
            sz
        );

        // Write 4-byte size header with continuation bit (bit 31) set
        let header: [u8; 4] = [
            ((sz >> 24) & 0xFF) as u8 | 0x80,
            ((sz >> 16) & 0xFF) as u8,
            ((sz >> 8) & 0xFF) as u8,
            (sz & 0xFF) as u8,
        ];

        self.writer.write_all(&header)?;
        self.writer.write_all(&payload)?;
        self.writer.flush()?;

        Ok(4 + payload.len())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use stellar_xdr::curr::{LedgerCloseMeta, LedgerCloseMetaV2, ReadXdr};

    /// A thread-safe in-memory writer that allows reading the buffer after writing.
    #[derive(Clone)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }
        fn data(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Helper to extract size from a 4-byte header with continuation bit.
    fn read_frame_size(data: &[u8], offset: usize) -> u32 {
        (((data[offset] & 0x7F) as u32) << 24)
            | ((data[offset + 1] as u32) << 16)
            | ((data[offset + 2] as u32) << 8)
            | (data[offset + 3] as u32)
    }

    #[test]
    fn test_write_one_header_format() {
        let buf = SharedBuffer::new();
        let mut stream = XdrOutputStream::from_writer(Box::new(buf.clone()));

        // Write a minimal LedgerCloseMeta::V2
        let meta = LedgerCloseMeta::V2(LedgerCloseMetaV2::default());
        let bytes_written = stream.write_one(&meta).unwrap();

        let data = buf.data();

        // Verify the header has the continuation bit set
        assert!(data[0] & 0x80 != 0, "continuation bit must be set");

        // Extract the size from the header
        let sz = read_frame_size(&data, 0);

        // Verify size matches payload
        assert_eq!(sz as usize, data.len() - 4);
        assert_eq!(bytes_written, data.len());

        // Verify the payload decodes back to the same value
        let decoded =
            LedgerCloseMeta::from_xdr(&data[4..], stellar_xdr::curr::Limits::none()).unwrap();
        assert_eq!(
            decoded.to_xdr(stellar_xdr::curr::Limits::none()).unwrap(),
            meta.to_xdr(stellar_xdr::curr::Limits::none()).unwrap()
        );
    }

    #[test]
    fn test_write_multiple_frames() {
        let buf = SharedBuffer::new();
        let mut stream = XdrOutputStream::from_writer(Box::new(buf.clone()));

        let meta1 = LedgerCloseMeta::V2(LedgerCloseMetaV2::default());
        let meta2 = LedgerCloseMeta::V2(LedgerCloseMetaV2::default());

        let bytes1 = stream.write_one(&meta1).unwrap();
        let bytes2 = stream.write_one(&meta2).unwrap();

        let data = buf.data();
        assert_eq!(data.len(), bytes1 + bytes2);

        // Decode first frame
        let sz1 = read_frame_size(&data, 0);
        let frame1_end = 4 + sz1 as usize;
        let _decoded1 =
            LedgerCloseMeta::from_xdr(&data[4..frame1_end], stellar_xdr::curr::Limits::none())
                .unwrap();

        // Decode second frame
        let sz2 = read_frame_size(&data, frame1_end);
        let frame2_end = frame1_end + 4 + sz2 as usize;
        let _decoded2 = LedgerCloseMeta::from_xdr(
            &data[frame1_end + 4..frame2_end],
            stellar_xdr::curr::Limits::none(),
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_from_fd() {
        use std::os::unix::io::IntoRawFd;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap();
        let fd = file.into_raw_fd();

        let mut stream = XdrOutputStream::from_fd(fd).unwrap();
        let meta = LedgerCloseMeta::V2(LedgerCloseMetaV2::default());
        stream.write_one(&meta).unwrap();
        drop(stream);

        // Read back and verify
        let data = std::fs::read(&path).unwrap();
        assert!(data[0] & 0x80 != 0);
        let sz = read_frame_size(&data, 0);
        let _decoded = LedgerCloseMeta::from_xdr(
            &data[4..4 + sz as usize],
            stellar_xdr::curr::Limits::none(),
        )
        .unwrap();
    }
}
