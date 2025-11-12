use base64::alphabet::STANDARD;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;

/// Base64 engine without padding.
pub const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);

/// Default key size in bytes for security operations.
///
/// # Legal compliance
///
/// A minimum of 112 bits is mandatory as per EN 18031.
pub const DEFAULT_KEY_SIZE: usize = 14;
