use crate::config::settings::JwtAlgorithm;
use crate::Claims;
use crate::{config::settings::JwtSettings, errors::JwtAuthError};
use jsonwebtoken::{encode, EncodingKey, Header};

pub fn encode_jwt<C: Claims>(claims: &C, settings: &JwtSettings) -> Result<String, JwtAuthError> {
    let header = match settings.algorithm {
        JwtAlgorithm::HS256 => Header::default(),
        JwtAlgorithm::RS256 => {
            let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
            header.typ = Some("JWT".to_owned());
            header
        }
    };

    let encoding_key = match settings.algorithm {
        JwtAlgorithm::HS256 => EncodingKey::from_secret(settings.secret.as_ref()),
        JwtAlgorithm::RS256 => EncodingKey::from_rsa_pem(settings.secret.as_ref())
            .map_err(|e| JwtAuthError::TokenEncodeError(e.to_string()))?,
    };

    encode(&header, claims, &encoding_key)
        .map_err(|e| JwtAuthError::TokenEncodeError(e.to_string()))
}
