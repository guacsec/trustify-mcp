use anyhow::Result;
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    http::header::AUTHORIZATION,
    middleware,
    middleware::Next,
    response::Response,
};
use std::{env, str::FromStr, sync::Arc};
use trustify_auth::{
    auth::AuthConfigArguments,
    authenticator::{Authenticator, config::SingleAuthenticatorClientConfig},
    authorizer::Authorizer,
};

#[derive(Clone)]
struct AppState {
    authenticator: Option<Arc<Authenticator>>,
    _authorizer: Arc<Authorizer>,
}

pub async fn protect_router(router: Router) -> Result<Router> {
    let auth_devmode = false;
    let openid_issuer_url =
        env::var("OPENID_ISSUER_URL").expect("Missing the OPENID_ISSUER_URL environment variable.");
    let open_client_id =
        env::var("OPENID_CLIENT_ID").expect("Missing the OPENID_CLIENT_ID environment variable.");
    let auth = AuthConfigArguments {
        disabled: is_auth_disabled(),
        config: None,
        clients: SingleAuthenticatorClientConfig {
            client_ids: vec![open_client_id],
            issuer_url: openid_issuer_url,
            required_audience: None,
            tls_insecure: false,
            tls_ca_certificates: vec![],
        },
    };
    let (authn, authz) = auth.split(auth_devmode)?.unzip();
    let authenticator = Authenticator::from_config(authn).await?.map(Arc::new);
    let _authorizer = Arc::new(Authorizer::new(authz));
    let state = Arc::new(AppState {
        authenticator,
        _authorizer,
    });

    // to keep the performance, attach the authentication layer only if there's an authenticator.
    // The alternative would be to always add the layer with the call to the authenticate function
    // here and, later on, in the authenticate function, if the state.authenticator is None,
    // let every request be executed
    match state.authenticator {
        None => Ok(router),
        Some(_) => {
            // Create protected SSE routes (require authorization)
            let protected_sse_router =
                router.layer(middleware::from_fn_with_state(state.clone(), authenticate));
            Ok(protected_sse_router)
        }
    }
}

fn is_auth_disabled() -> bool {
    let auth_disabled =
        bool::from_str(&env::var("AUTH_DISABLED").unwrap_or(false.to_string())).unwrap_or(false);
    if auth_disabled {
        tracing::warn!("Auth disabled");
    }
    auth_disabled
}

async fn authenticate(
    State(state): State<Arc<AppState>>,
    // you can also add extractors here, e.g. the `HeaderMap` extractor
    // headers: HeaderMap,
    // but the last extractor must implement `FromRequest` which `Request` does
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match &state.authenticator {
        Some(authenticator) => {
            if let Some(bearer) = request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|auth| auth.to_str().ok())
                .and_then(|auth| auth.strip_prefix("Bearer "))
            {
                match authenticator.validate_token(&bearer).await.is_ok() {
                    true => Ok(next.run(request).await),
                    false => Err(StatusCode::UNAUTHORIZED),
                }
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        // if the authenticate function had been attached to the router (authentication enabled)
        // but the state.authenticator is now None, then the request is unauthorized
        // because it's an unexpected situation so better keep safety first
        None => Err(StatusCode::UNAUTHORIZED),
    }
}
