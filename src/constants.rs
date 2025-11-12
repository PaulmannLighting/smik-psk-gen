use base64::alphabet::STANDARD;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;

pub const BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);
pub const DEFAULT_KEY_SIZE: usize = 14; // 112 bits are mandatory as per EN 18031.
