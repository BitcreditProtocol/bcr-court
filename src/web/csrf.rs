use anyhow::anyhow;
use bitcoin::{
    base58,
    hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256::Hash as Sha256},
};
use rand::{distr::Alphanumeric, prelude::*};
use tower_sessions::Session;

use crate::web::CSRF_TOKEN;

fn gen_token(session_id: &str) -> Result<String, anyhow::Error> {
    let rng = rand::rng();
    let token: String = rng
        .sample_iter(&Alphanumeric)
        .take(42)
        .map(char::from)
        .collect();

    let mut mac: HmacEngine<Sha256> = HmacEngine::new(session_id.as_bytes());
    mac.input(token.as_bytes());
    let hmac_result: Hmac<Sha256> = Hmac::from_engine(mac);

    let bytes = hmac_result.to_byte_array();
    Ok(base58::encode(&bytes))
}

pub async fn gen_csrf(session: &Session) -> Result<String, anyhow::Error> {
    if let Some(session_token) = session.get::<String>(CSRF_TOKEN).await? {
        Ok(session_token)
    } else {
        let token = gen_token(&session.id().unwrap_or_default().to_string())?;
        session.insert(CSRF_TOKEN, &token).await?;
        Ok(token)
    }
}

pub async fn verify_csrf(csrf_token: &str, session: &Session) -> Result<(), anyhow::Error> {
    if let Some(session_token) = session.get::<String>(CSRF_TOKEN).await? {
        if csrf_token != session_token {
            return Err(anyhow!("invalid csrf"));
        }
    } else {
        return Err(anyhow!("invalid csrf"));
    }
    Ok(())
}
