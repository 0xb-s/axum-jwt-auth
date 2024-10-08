use crate::{decode_jwt, Claims};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::future::BoxFuture;

use crate::config::settings::JwtSettings;

use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};
pub struct JwtAuthLayer<C>
where
    C: Claims + Send + Sync + 'static,
{
    settings: Arc<JwtSettings>,
    _marker: PhantomData<C>,
}

impl<C> JwtAuthLayer<C>
where
    C: Claims + Send + Sync + 'static,
{
    pub fn new(settings: JwtSettings) -> Self {
        Self {
            settings: Arc::new(settings),
            _marker: PhantomData,
        }
    }
}

impl<S, C> Layer<S> for JwtAuthLayer<C>
where
    C: Claims + Send + Sync + 'static,
{
    type Service = JwtAuthMiddleware<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthMiddleware {
            inner,
            settings: self.settings.clone(),
            _marker: PhantomData,
        }
    }
}

pub struct JwtAuthMiddleware<S, C>
where
    C: Claims + Send + Sync + 'static,
{
    inner: S,
    settings: Arc<JwtSettings>,
    _marker: PhantomData<C>,
}

impl<S, C, B> Service<axum::http::Request<B>> for JwtAuthMiddleware<S, C>
where
    C: Claims + Send + Sync + 'static,
    S: Service<axum::http::Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<B>) -> Self::Future {
        let settings = self.settings.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let auth_header = req.headers().get(axum::http::header::AUTHORIZATION);
            let token = if let Some(auth_header) = auth_header {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        Some(auth_str.trim_start_matches("Bearer ").to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let token = match token {
                Some(t) => t,
                None => {
                    return Ok((
                        StatusCode::UNAUTHORIZED,
                        "Missing or invalid Authorization header",
                    )
                        .into_response())
                }
            };

          
            match decode_jwt::<C>(&token, &settings) {
                Ok(token_data) => {
                 
                    if !token_data.claims.validate(&settings) {
                        return Ok(
                            (StatusCode::UNAUTHORIZED, "Invalid token claims").into_response()
                        );
                    }

                
                    let mut req = req;
                    req.extensions_mut().insert(token_data.claims);

                    inner.call(req).await
                }
                Err(e) => {
                    return Ok((e.status_code(), e.message()).into_response());
                }
            }
        })
    }
}
