use crate::config::settings::JwtSettings;
use chrono::Utc;
use serde::{Deserialize, Serialize};

pub trait Claims: Serialize + for<'de> Deserialize<'de> + ValidatableClaims + Clone {}

pub trait ValidatableClaims {
    fn validate(&self, settings: &JwtSettings) -> bool;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StandardClaims {
    pub sub: String,
    pub exp: usize,
    pub iss: String,
    pub roles: Vec<String>,
}

impl ValidatableClaims for StandardClaims {
    fn validate(&self, settings: &JwtSettings) -> bool {
        if self.iss != settings.issuer {
            return false;
        }

        let current_timestamp = Utc::now().timestamp() as usize;
        if self.exp < current_timestamp {
            return false;
        }

        true
    }
}

impl Claims for StandardClaims {}
