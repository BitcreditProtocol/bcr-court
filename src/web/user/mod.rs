use axum::{
    Form,
    extract::State,
    response::{IntoResponse, Redirect},
};
use bcr_ebill_core::{NodeId, util::BcrKeys};
use tower_sessions::Session;
use tracing::{error, warn};

mod data;

use crate::{
    Ctx,
    web::{
        NODE_ID, Result,
        csrf::{gen_csrf, verify_csrf},
        error::Error,
        rate_limit::RealIp,
        templates::{
            Auth, AuthUser, HtmlTemplate, UserCreateKeysetTemplate, UserKeysetTemplate,
            UserLoginTemplate,
        },
        user::data::{CreateKeysetData, LoginData},
    },
};

#[tracing::instrument(level = tracing::Level::DEBUG, skip(auth, session))]
pub async fn create_keyset(session: Session, auth: Auth) -> Result<impl IntoResponse> {
    tracing::debug!("create keyset called");
    let template = UserCreateKeysetTemplate {
        auth,
        csrf_token: gen_csrf(&session).await.map_err(|_| Error::Internal)?,
    };
    Ok(HtmlTemplate(template))
}

#[tracing::instrument(level = tracing::Level::DEBUG, skip(ctx, session, payload, auth))]
pub async fn do_create_keyset(
    RealIp(ip): RealIp,
    session: Session,
    auth: Auth,
    State(ctx): State<Ctx>,
    Form(payload): Form<CreateKeysetData>,
) -> Result<impl IntoResponse> {
    tracing::debug!("do create keyset called");
    let mut rate_limiter = ctx.rate_limiter.lock().await;
    let allowed = rate_limiter.check(&ip.to_string(), None);
    drop(rate_limiter);
    if !allowed {
        warn!("Rate limited req from {}", &ip.to_string(),);
        return Err(Error::TooManyRequests);
    }

    verify_csrf(&payload.csrf_token, &session)
        .await
        .map_err(|_| Error::Unauthorized)?;
    if !payload.validate() {
        return Err(Error::BadRequest("invalid payload".to_string()));
    }

    let (keypair, seed_phrase) = BcrKeys::new_with_seed_phrase().map_err(|e| {
        error!("error creating key pair: {e}");
        Error::Internal
    })?;
    let node_id = NodeId::new(keypair.pub_key(), ctx.config.bitcoin_network);

    ctx.user_store
        .create_user(&payload.name, &node_id, &keypair.get_private_key())
        .await
        .map_err(|e| {
            error!("error creating user: {e}");
            Error::Internal
        })?;

    let template = UserKeysetTemplate {
        auth,
        name: payload.name.clone(),
        node_id: node_id.to_string(),
        seed_phrase,
    };

    Ok(HtmlTemplate(template))
}

#[tracing::instrument(level = tracing::Level::DEBUG, skip(session, auth))]
pub async fn login(session: Session, auth: Auth) -> Result<impl IntoResponse> {
    tracing::debug!("login called");
    let template = UserLoginTemplate {
        auth,
        csrf_token: gen_csrf(&session).await.map_err(|_| Error::Internal)?,
    };
    Ok(HtmlTemplate(template))
}

#[tracing::instrument(level = tracing::Level::DEBUG, skip(ctx, session, payload))]
pub async fn do_login(
    RealIp(ip): RealIp,
    session: Session,
    State(ctx): State<Ctx>,
    Form(payload): Form<LoginData>,
) -> Result<impl IntoResponse> {
    tracing::debug!("do login called");
    let mut rate_limiter = ctx.rate_limiter.lock().await;
    let allowed = rate_limiter.check(&ip.to_string(), None);
    drop(rate_limiter);
    if !allowed {
        warn!("Rate limited req from {}", &ip.to_string(),);
        return Err(Error::TooManyRequests);
    }

    verify_csrf(&payload.csrf_token, &session)
        .await
        .map_err(|_| Error::Unauthorized)?;
    if !payload.validate() {
        return Err(Error::BadRequest("invalid payload".to_string()));
    }

    let keypair = BcrKeys::from_seedphrase(&payload.password).map_err(|_| Error::Unauthorized)?;
    let node_id = NodeId::new(keypair.pub_key(), ctx.config.bitcoin_network);

    let user = match ctx
        .user_store
        .get_by_key(&node_id, &keypair.get_private_key())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return Err(Error::Unauthorized),
        Err(e) => {
            error!("error fetching user: {e}");
            return Err(Error::Unauthorized);
        }
    };

    // add user to the session
    session
        .insert(
            NODE_ID,
            AuthUser {
                node_id: user.node_id.to_string(),
                name: user.name.clone(),
            },
        )
        .await
        .map_err(|e| {
            error!("error putting user in session: {e}");
            Error::Internal
        })?;

    Ok(Redirect::to("/shared_bills").into_response())
}

#[tracing::instrument(level = tracing::Level::DEBUG, skip(session))]
pub async fn logout(session: Session) -> Result<impl IntoResponse> {
    tracing::debug!("logout called");
    session.delete().await.map_err(|e| {
        error!("Error logging out: {e}");
        Error::Internal
    })?;
    Ok(Redirect::to("/"))
}
