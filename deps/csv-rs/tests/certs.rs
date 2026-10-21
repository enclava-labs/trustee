mod cert;

/// The public HRK certificate.
pub const HSK: &[u8] = include_bytes!("test_data/hsk.cert");
pub const CEK: &[u8] = include_bytes!("test_data/cek.cert");
