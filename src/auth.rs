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
use std::{env, sync::Arc};
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
    if is_auth_disabled() {
        return Ok(router);
    }

    let auth_devmode = false;
    let openid_issuer_url =
        env::var("OPENID_ISSUER_URL").expect("Missing the OPENID_ISSUER_URL environment variable.");
    let open_client_id =
        env::var("OPENID_CLIENT_ID").expect("Missing the OPENID_CLIENT_ID environment variable.");
    let auth = AuthConfigArguments {
        disabled: false,
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
    let auth_disabled = parse_auth_disabled(env::var("AUTH_DISABLED").ok().as_deref());
    if auth_disabled {
        tracing::warn!("Auth disabled");
    }
    auth_disabled
}

fn parse_auth_disabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case("true"))
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

#[cfg(test)]
mod tests {
    use super::{parse_auth_disabled, protect_router};
    use axum::Router;
    use std::{env, sync::LazyLock};
    use tokio::sync::Mutex;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn auth_disabled_requires_true_value() {
        assert!(parse_auth_disabled(Some("true")));
        assert!(parse_auth_disabled(Some("TRUE")));
        assert!(!parse_auth_disabled(Some("false")));
        assert!(!parse_auth_disabled(Some("invalid")));
        assert!(!parse_auth_disabled(None));
    }

    #[tokio::test]
    async fn disabled_auth_does_not_require_oidc_configuration() {
        let _lock = ENV_LOCK.lock().await;
        let variables = [
            "AUTH_DISABLED",
            "OPENID_ISSUER_URL",
            "OPENID_CLIENT_ID",
            "OPENID_CLIENT_SECRET",
        ];
        let previous = variables
            .iter()
            .map(|name| (*name, env::var_os(name)))
            .collect::<Vec<_>>();

        unsafe {
            env::set_var("AUTH_DISABLED", "true");
            env::remove_var("OPENID_ISSUER_URL");
            env::remove_var("OPENID_CLIENT_ID");
            env::remove_var("OPENID_CLIENT_SECRET");
        }
        let result = protect_router(Router::new()).await;

        unsafe {
            for (name, value) in previous {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }

        assert!(result.is_ok());
    }
}
