use crate::config::settings::JwtAlgorithm;
use crate::Claims;
use crate::{config::settings::JwtSettings, errors::JwtAuthError};
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation};

pub fn decode_jwt<C: Claims>(
    token: &str,
    settings: &JwtSettings,
) -> Result<TokenData<C>, JwtAuthError> {
    let mut validation = Validation::new(match settings.algorithm {
        JwtAlgorithm::HS256 => jsonwebtoken::Algorithm::HS256,
        JwtAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
    });
    validation.set_audience::<String>(&[]);
    validation.set_issuer(&[settings.issuer.clone()]);

    let decoding_key = match settings.algorithm {
        JwtAlgorithm::HS256 => DecodingKey::from_secret(settings.secret.as_ref()),
        JwtAlgorithm::RS256 => DecodingKey::from_rsa_pem(settings.secret.as_ref())
            .map_err(|e| JwtAuthError::TokenDecodeError(e.to_string()))?,
    };

    decode::<C>(token, &decoding_key, &validation).map_err(|e| match *e.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidToken => JwtAuthError::InvalidToken,
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtAuthError::ExpiredToken,
        _ => JwtAuthError::TokenDecodeError(e.to_string()),
    })
}
