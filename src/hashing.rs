use sha2::Sha256;
use sha3::{Digest, Sha3_512};
use base64::{engine::general_purpose, Engine};

///Generate a Sha3_512 hash for the given String encoded with base64 URLSAFE no padding
pub(crate) fn get_hash_string_base64(input: &str) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}


///Generate a SHA2-sha256 hash for the given String encoded with base64 URLSAFE no padding
pub(crate) fn get_hash_string_sha256_base64(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

//************** */
//UNIT TEST    **/
//************* */
#[cfg(test)]
mod hashing_tests {
    use super::*;

    #[test]
    fn test_hash_known_input() {
        let input = "hello world";
        let expected_base64 = "hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0_4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg"; //URLSAFE + Nopadding adjusted from https://emn178.github.io/online-tools/sha3_512.html
        assert_eq!(get_hash_string_base64(&input),expected_base64);
    }
}