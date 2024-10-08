use anyhow::{anyhow, Result};
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1::DecodeRsaPublicKey, RsaPrivateKey, RsaPublicKey};

pub fn load_rsa_private_key(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| anyhow!("Failed to load RSA private key: {}", e))
}

pub fn load_rsa_public_key(pem: &str) -> Result<RsaPublicKey> {
    RsaPublicKey::from_pkcs1_pem(pem).map_err(|e| anyhow!("Failed to load RSA public key: {}", e))
}
