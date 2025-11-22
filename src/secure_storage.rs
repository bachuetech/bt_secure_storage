use std::{collections::HashSet, error::Error};
use bt_logger::{get_error, get_fatal, log_error};
use bt_string_utils::generate_url_safe_string;
use keyring::Entry;

// AES-GCM with 256-bit key
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce, aead::{Aead, OsRng}}; 
use base91::{slice_decode, slice_encode};

use pbkdf2::pbkdf2_hmac;
//use base64::{engine::general_purpose, Engine};
use whoami::username;

use crate::hashing::get_hash_string_base64;

/// Maximum size of a string for generating a service ID.
const MAX_SIZE: usize = 256;

/// Represents a vault for storing secrets.
pub struct SecretVault{
    /// Prefix used to construct service IDs.
    service_prefix: String,

    /// User's username, used to gain access to the secret store.
    user_name: String, 
}

impl SecretVault {
    /// Generates a service ID by hashing the provided service name with the vault's prefix and salt.
    /// 
    /// # Returns
    /// The hashed service ID as a string, truncated to `MAX_SIZE` characters.    
    fn get_service_id(&self, service: &str) -> String{
        let svr_name = format!("{}{}",self.service_prefix,service);
        let svr = get_hash_string_base64(&svr_name);
        //log_verbose!("get_service_id","Full Service ID: {}",svr);
        svr.chars().take(MAX_SIZE).collect()
    }

    /// Creates a new `SecretVault` instance with the provided prefix and user's username.
    ///
    /// # Returns
    /// The newly created `SecretVault` instance.    
    pub fn new(srv_prefix: &str) -> Self{
        let usr_name = username().chars().take(MAX_SIZE).collect(); 
        Self { service_prefix: srv_prefix.to_owned(), user_name: usr_name }
    }

    /// Stores a secret with the provided service name and password.
    ///
    /// # Parameters
    /// * `service`: The name of the service storing the secret.
    /// * `secret`: The password to use for authentication.
    ///
    /// # Returns
    /// A result indicating whether the operation was successful or not.    
    pub fn store_secret(&self, service: &str, secret: &str) -> Result<(), Box<dyn Error>> {
        let entry =  Entry::new(&self.get_service_id(service), &self.user_name)?; 
        entry.set_password(secret)?;
        Ok(())
    }

    /// Retrieves a secret by its name.
    ///
    /// # Parameters
    /// * `service`: The name of the service storing the secret.
    ///
    /// # Returns
    /// A result containing the retrieved password as a string, or an error if the operation failed.    
    pub fn retrieve_secret(&self, service: &str) -> Result<String, keyring::Error> {
        let entry = Entry::new(&self.get_service_id(service), &self.user_name)?;
        let secret = entry.get_password()?;
        Ok(secret)
    }

    /// Stores an attribute set with the provided service name and attributes.
    ///
    /// # Parameters
    /// * `service`: The name of the service storing the attribute set.
    /// * `attributes`: A set of strings representing the attribute values.
    ///
    /// # Returns
    /// A result indicating whether the operation was successful or not.    
    pub fn store_attribute_set(&self, service: &str, attributes: &HashSet<String>) -> Result<(), Box<dyn Error>> {
        let map = serde_json::to_string(attributes)?;
        self.store_secret(service, &map)
    }

    /// Retrieves an attribute set by its name.
    ///
    /// # Parameters
    /// * `service`: The name of the service storing the attribute set.
    ///
    /// # Returns
    /// A result containing the retrieved attribute set as a string, or an error if the operation failed.    
    pub fn retrieve_attribute_set(&self,service: &str) -> Result<HashSet<String>, Box<dyn Error>>{
        let map =self.retrieve_secret(service)?;
        let set_from_values: HashSet<String> = serde_json::from_str(&map)?;
        Ok(set_from_values)
    }


    /// Deletes a secret by its name.
    ///
    /// # Parameters
    /// * `service`: The name of the service storing the secret.
    ///
    /// # Returns
    /// A result indicating whether the operation was successful or not.    
    pub fn delete_secret(&self, service: &str) -> Result<(), keyring::Error> {
        let entry = Entry::new(&self.get_service_id(service), &self.user_name)?;
        entry.delete_credential()
    }
}

/// Number of iterations for password-based key derivation.
const ITERATIONS: u32 = 100_000;

/// Length of the secret key in bytes.
const KEY_LEN: usize = 32;

/// Represents a cipher for encrypting and decrypting secrets.
#[derive(Debug)]
pub struct SecretCipher{
    salt: String,
}

impl SecretCipher {
    /// Creates a new `SecretCipher` instance with a randomly generated salt.
    ///
    /// # Returns
    /// The newly created `SecretCipher` instance.    
    pub fn new() -> Self{
        const SECRET_CIPHER_SERVICE_PREFIX: &str = "secret_cipher_service";
        const SALT: &str = "SALT";
        let sv = SecretVault::new(SECRET_CIPHER_SERVICE_PREFIX);
        let s = sv.retrieve_secret(SALT);

        let cipher_salt = if s.is_ok() { 
                                        s.unwrap() 
                                    } else {
                                        let new_salt = generate_url_safe_string(32);
                                        sv.store_secret(SALT, &new_salt).expect(&get_fatal!("new","Cannot securely save encryption data!"));
                                        new_salt
                                    };
        SecretCipher{ salt:cipher_salt }
    }

    /// Derives a key from the provided password using password-based key derivation.
    ///
    /// # Parameters
    /// * `password`: The password to use for key derivation.
    ///
    /// # Returns
    /// The derived key as a byte array.    
    fn derive_key(&self, password: &str) -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), self.salt.as_bytes(), ITERATIONS, &mut key);
        key
    }

    /// Encrypts the provided secret using the derived key and random nonce.
    ///
    /// # Parameters
    /// * `secret`: The secret to encrypt.
    /// * `key_str`: The password used for encryption.
    ///
    /// # Returns
    /// A tuple containing the encrypted ciphertext as a base91-encoded string, and the random nonce as a base64-encoded string.    
    pub fn encrypt_secret(&self, secret: &str, key_str: &str) -> Result<(String, String),Box< dyn Error>> {
        // Hash the key string to get a 32-byte key
        let key_hash: &[u8; 32] = &self.derive_key(key_str);
        let key: &Key<Aes256Gcm>  = key_hash.into(); 
        let cipher = Aes256Gcm::new(key);

        // Generate a random 12-byte nonce
        //let nonce_bytes: [u8; 12] =  rand::rng().random();
        let nonce =  Aes256Gcm::generate_nonce(&mut OsRng); //Nonce::from_slice(&nonce_bytes);

        // Encrypt the secret
        let ciphertext = match cipher.encrypt(&nonce, secret.as_bytes()){
            Ok(c) => c,
            Err(e) => return Err(get_error!("encrypt_secret","Unable to encrypt secret. Error: {}",e).into()),
        };

        // Return base64-encoded ciphertext and nonce
        //Ok( ( general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext),  general_purpose::URL_SAFE_NO_PAD.encode(&nonce) ) ) 
        // Return base91-encoded ciphertext and nonce
        Ok( ( String::from_utf8(slice_encode(&ciphertext))?,  String::from_utf8(slice_encode(&nonce))? ) ) 
    }

    /// Decrypts the provided ciphertext using the derived key and random nonce.
    ///
    /// # Parameters
    /// * `ciphertext_b64`: The base91-encoded ciphertext to decrypt.
    /// * `nonce_b91`: The base91-encoded nonce used for decryption.
    /// * `key_str`: The password used for decryption.
    ///
    /// # Returns
    /// A result containing the decrypted plaintext as a string, or an error if the operation failed.    
    pub fn decrypt_secret(&self, ciphertext_b91: &str, nonce_b91: &str, key_str: &str) -> Result<String, Box< dyn Error>>{
        let key_hash: &[u8; 32] = &self.derive_key(key_str); 
        let key: &Key<Aes256Gcm> = key_hash.into(); 
        let cipher = Aes256Gcm::new(key);

        let nonce_bytes = slice_decode(nonce_b91.as_bytes()); //general_purpose::URL_SAFE_NO_PAD.decode(nonce_b64)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = slice_decode(ciphertext_b91.as_bytes()); //general_purpose::URL_SAFE_NO_PAD.decode(ciphertext_b64)?;
        match cipher.decrypt(nonce, ciphertext.as_ref()){
            Ok(plaintext) => Ok(String::from_utf8(plaintext)?),
            Err(e) => {
                log_error!("decrypt_secret","");
                Err(get_error!("decrypt_secret","Decryption failed. Error: {}", e).into())
            },
        }
    }
}


#[cfg(test)]
mod enc_dec_tests {
    use bt_logger::{build_logger, log_verbose};

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        build_logger("BACHUETECH", "enc_dec_tests", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_ERROR, None);

        let cipher = SecretCipher::new();
        let key = "my-auth0-client-secret";
        let secret = "super-sensitive-token";

        let (encrypted, nonce) = cipher.encrypt_secret(secret, key).unwrap();
        let decrypted = cipher.decrypt_secret(&encrypted, &nonce, key);

        assert_eq!(decrypted.unwrap(), secret);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        build_logger("BACHUETECH", "enc_dec_tests", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_OUT, None);
        let cipher = SecretCipher::new();        
        let key = "correct-key";
        let wrong_key = "wrong-key";
        let secret = "top-secret";

        let (encrypted, nonce) = cipher.encrypt_secret(secret, key).unwrap();
        let result = cipher.decrypt_secret(&encrypted, &nonce, wrong_key);
        log_verbose!("test_decrypt_with_wrong_key_fails","DEC: {:?}",result);
        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_decrypt_outputs_different_times_success() {
        build_logger("BACHUETECH", "enc_dec_tests", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_ERROR, None);
        let cipher = SecretCipher::new();        
        let key = "same-key";
        let secret = "same-secret";

        let (enc1, _) = cipher.encrypt_secret(secret, key).unwrap();        
        let (enc2, _) = cipher.encrypt_secret(secret, key).unwrap();

        assert_ne!(enc1, enc2, "Ciphertext should not differ due to dec times");
    }


    #[test]
    fn test_decrypt_outputs_different_ciphertext_each_time() {
        build_logger("BACHUETECH", "enc_dec_tests", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_ERROR, None);
        let cipher = SecretCipher::new();        
        let key = "same-key";
        let secret = "same-secret";

        let (enc1, nonce) = cipher.encrypt_secret(secret, key).unwrap();
        let cipher = SecretCipher::new();         
        let dec1 = cipher.decrypt_secret(&enc1, &nonce, key);
        let cipher = SecretCipher::new();
        let dec2 = cipher.decrypt_secret(&enc1, &nonce, key);  

        log_verbose!("test_decrypt_outputs_different_ciphertext_each_time","dec1: {:?} dec2: {:?}",dec1,dec2);
        let d1 = dec1.unwrap();
        assert_eq!(d1, secret);
        let d2 = dec2.unwrap();
        log_verbose!("test_decrypt_outputs_different_ciphertext_each_time","d1: '{}'. d2: '{}'",d1,d2);
        assert_eq!(d1, d2, "Ciphertext should not differ secret");
    }    
}


#[cfg(test)]
mod secret_vault_tests {
    use super::*;
    use std::{collections::HashSet, sync::Once};

    use bt_logger::{build_logger, log_verbose, LogLevel, LogTarget};
    use ctor::dtor;

   
    static INIT: Once = Once::new();
    fn ini_log() {
        INIT.call_once(|| {
            build_logger("BACHUETECH", "UNIT TEST RUST JOB_SEEK_TRK_DX", LogLevel::VERBOSE, LogTarget::STD_ERROR, None );     
        });
    }

    #[test]
    fn test_new_secret_vault() {
        let vault = SecretVault::new("test_prefix");
        assert_eq!(vault.service_prefix, "test_prefix");
        // Note: user_name is tested via whoami::username which is hard to mock
        // so we just check it's not empty
        assert!(!vault.user_name.is_empty());
    }

    #[test]
    fn test_get_service_id() {
        let vault = SecretVault::new("test_prefix");
        let service_name = "test_service";
        let service_id = vault.get_service_id(service_name);
        
        // Check that the result is a valid string and not empty
        assert!(!service_id.is_empty());
        
        // Check that it's truncated to MAX_SIZE
        assert!(service_id.len() <= MAX_SIZE);
    }

    #[test]
    fn test_get_service_id_with_long_service_name() {
        ini_log();
        let vault = SecretVault::new("test_prefix");
        let long_service_name = "a".repeat(MAX_SIZE + 300); // Long service name
        let service_id = vault.get_service_id(&long_service_name);
        // Should still be truncated to <= MAX_SIZE
        assert!(service_id.len() <= MAX_SIZE);
    }

    #[test]
    fn test_store_secret() {
        // Note: This test requires a real keyring backend to be available
        let vault = SecretVault::new("test_prefix");
        let service_name = "test_service";
        let secret = "test_secret";
        
        let result = vault.store_secret(service_name, secret);
        assert!(result.is_ok()); // or assert!(result.is_err()) depending on environment
    }

    #[test]
    fn test_retrieve_unknown_secret() {
        // Note: This test requires a real keyring backend to be available
        let vault = SecretVault::new("test_prefix");
        let service_name = "invalid_test_service_unknown";
        
        // This will fail if no keyring backend is available or if no secret exists
        let result = vault.retrieve_secret(service_name);
        assert!(result.is_err()); // Should fail because no secret was stored
    }

    #[test]
    fn test_store_attribute_set() {
        // Note: This test requires a real keyring backend to be available
        let vault = SecretVault::new("test_prefix");
        let mut attributes = HashSet::new();
        attributes.insert("attr1".to_string());
        attributes.insert("attr2".to_string());
        let service_name = "test_service";
        
        let result = vault.store_attribute_set(service_name, &attributes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_secret() {
        ini_log();
        // Note: This test requires a real keyring backend to be available
        let vault = SecretVault::new("test_prefix");
        let service_name = "test_service_delete";
        let _ = vault.store_secret(service_name, "delete");
        
        let result = vault.delete_secret(service_name);
        log_verbose!("test_delete_secret","delete rest: {:?}",result);
        assert!(result.is_ok());     
    }


    #[test]
    fn test_store_and_retrieve_secret() {
        ini_log();
        // Note: This test requires a real keyring backend to be available
        let vault = SecretVault::new("test_prefix");
        let service_name = "test_service_str";
        let secret = "test_secret";
        
        // Store a secret
        let store_result = vault.store_secret(service_name, secret);
        assert!(store_result.is_ok());
        
        // Retrieve the secret
        let retrieve_result = vault.retrieve_secret(service_name);
log_verbose!("test_store_and_retrieve_secret","Retrieved Secret: {:?}",retrieve_result);
        assert!(retrieve_result.is_ok());
        assert_eq!(retrieve_result.unwrap(), secret);
    }

    #[test]
    fn test_store_and_retrieve_attribute_set() {
        ini_log();
        // Note: This test requires a real keyring backend to be available
        let vault = SecretVault::new("test_prefix");
        let mut attributes = HashSet::new();
        attributes.insert("attr1".to_string());
        attributes.insert("attr2".to_string());
        let service_name = "test_service_set";
        
        // Store an attribute set
        let store_result = vault.store_attribute_set(service_name, &attributes);
        assert!(store_result.is_ok());
        
        // Retrieve the attribute set
        let retrieve_result = vault.retrieve_attribute_set(service_name);
        log_verbose!("test_store_and_retrieve_attribute_set","Retrieve Result: {:?}",retrieve_result);
        assert!(retrieve_result.is_ok());
        assert_eq!(retrieve_result.unwrap(), attributes);
    }

    #[dtor]
    fn after_all() {
        ini_log();
        let vault = SecretVault::new("test_prefix");
        vault.delete_secret("test_service_set");
        vault.delete_secret("test_service_str");
        vault.delete_secret("test_service");
        vault.delete_secret("invalid_test_service_unknown");
        log_verbose!("clean_storage","Done Cleaning");
    }
}