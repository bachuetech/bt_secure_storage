# Project Title
BT Secure Storage

## Description
This library provides a simple secret vault and encryption system using the whoami crate to get the username and the keyring backend to store secrets securely. It also includes an encryption/decryption system based on AES.

## Features
* Secure Secret Storage: Store sensitive data like passwords, API keys, or tokens securely.
* Encryption/Decryption: Use AES for encrypting and decrypting data.
* Test Cases: Unit tests are included to verify the functionality of the library.

## Usage
```
    let vault = SecretVault::new("my_app");
    let cipher = SecretCipher::new();

    // Store a secret securely
    let service_name = "my_service";
    let secret = "super_sensitive_data";
    vault.store_secret(service_name, secret)?;

    // Retrieve the stored secret
    let retrieved_secret = vault.retrieve_secret(service_name)?;
    assert_eq!(retrieved_secret, secret);

    // Encrypt and decrypt data using AES
    let encrypted_data = cipher.encrypt_secret(secret, "my_key")?;
    let decrypted_data = cipher.decrypt_secret(&encrypted_data.0, &encrypted_data.1, "my_key")?;
```

## Version History
* 0.1.0
    * Initial Release
* 0.1.1
    * Make mod public    

## License
GPL-3.0-only
