use http::StatusCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtAuthError {
    #[error("Missing Authorization Header")]
    MissingAuthHeader,

    #[error("Invalid Authorization Header")]
    InvalidAuthHeader,

    #[error("Token Decoding Error: {0}")]
    TokenDecodeError(String),

    #[error("Token Encoding Error: {0}")]
    TokenEncodeError(String),

    #[error("Invalid Token")]
    InvalidToken,

    #[error("Expired Token")]
    ExpiredToken,

    #[error("Invalid Claims")]
    InvalidClaims,

    #[error("Internal Server Error")]
    InternalError,
}

impl JwtAuthError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            JwtAuthError::MissingAuthHeader
            | JwtAuthError::InvalidAuthHeader
            | JwtAuthError::InvalidToken
            | JwtAuthError::ExpiredToken
            | JwtAuthError::InvalidClaims => StatusCode::UNAUTHORIZED,
            JwtAuthError::TokenDecodeError(_)
            | JwtAuthError::TokenEncodeError(_)
            | JwtAuthError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(&self) -> String {
        self.to_string()
    }
}
