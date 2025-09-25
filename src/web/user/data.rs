use bcr_ebill_core::util::BcrKeys;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateKeysetData {
    pub csrf_token: String,
    pub name: String,
}

impl CreateKeysetData {
    pub fn validate(&self) -> bool {
        if self.name.is_empty() || self.name.len() > 30 {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginData {
    pub csrf_token: String,
    pub password: String,
}

impl LoginData {
    pub fn validate(&self) -> bool {
        if self.password.is_empty() {
            return false;
        }

        if BcrKeys::from_seedphrase(&self.password).is_err() {
            return false;
        }

        true
    }
}
