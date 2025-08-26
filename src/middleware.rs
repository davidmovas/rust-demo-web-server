//! Модуль с промежуточными обработчиками (middleware) для веб-сервера
//!
//! Содержит компоненты для обработки запросов и ответов,
//! такие как аутентификация, логирование и обработка ошибок.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use tracing::{error, info};

use crate::{
    config::AppConfig,
    models::{
        api::{ApiResponse, ApiStatus},
        auth::Claims,
    },
};

/// Модуль с middleware для аутентификации
pub mod auth {
    use super::*;

    /// Извлекает и проверяет JWT токен из заголовка Authorization
    pub async fn require_auth(
        State(config): State<Arc<AppConfig>>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, Response> {
        // Получаем заголовок Authorization
        let auth_header = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok())
            .and_then(|value| {
                if value.starts_with("Bearer ") {
                    Some(value[7..].to_string())
                } else {
                    None
                }
            });

        // Если заголовок отсутствует или неверного формата, возвращаем ошибку
        let token = auth_header.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Отсутствует или неверный формат токена аутентификации",
                )),
            )
                .into_response()
        })?;

        // Проверяем токен
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(config.jwt.secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| {
            error!("Ошибка проверки токена: {:?}", e);
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("Недействительный токен аутентификации")),
            )
                .into_response()
        })?;

        // Добавляем данные пользователя в расширения запроса
        request.extensions_mut().insert(token_data.claims);

        // Продолжаем обработку запроса
        Ok(next.run(request).await)
    }

    /// Проверяет, что пользователь имеет роль администратора
    pub async fn require_admin(
        request: Request,
        next: Next,
    ) -> Result<Response, Response> {
        // Получаем claims из расширений запроса
        let claims = request.extensions().get::<Claims>().ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Ошибка аутентификации: отсутствуют данные пользователя",
                )),
            )
                .into_response()
        })?;

        // Проверяем роль пользователя
        if claims.role != "admin" {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiResponse::<()>::error(
                    "Доступ запрещен: требуются права администратора",
                )),
            )
                .into_response());
        }

        // Продолжаем обработку запроса
        Ok(next.run(request).await)
    }
}

/// Модуль с middleware для логирования
pub mod logging {
    use super::*;
    use std::time::Instant;

    /// Логирует информацию о запросе и времени его выполнения
    pub async fn log_request(request: Request, next: Next) -> Response {
        let path = request.uri().path().to_owned();
        let method = request.method().clone();

        info!("Получен запрос: {} {}", method, path);

        let start = Instant::now();
        let response = next.run(request).await;
        let duration = start.elapsed();

        info!(
            "Запрос {} {} обработан за {:?} со статусом {}",
            method,
            path,
            duration,
            response.status()
        );

        response
    }
}

/// Модуль с middleware для обработки ошибок
pub mod error_handling {
    use super::*;
    use axum::http::Request as HttpRequest;
    use std::any::Any;
    use std::panic::{self, AssertUnwindSafe};
    use futures::future::BoxFuture;
    use tower::{Layer, Service};

    /// Слой для перехвата паник в обработчиках
    #[derive(Clone)]
    pub struct CatchPanicLayer;

    impl<S> Layer<S> for CatchPanicLayer {
        type Service = CatchPanicService<S>;

        fn layer(&self, service: S) -> Self::Service {
            CatchPanicService { service }
        }
    }

    /// Сервис для перехвата паник
    #[derive(Clone)]
    pub struct CatchPanicService<S> {
        service: S,
    }

    impl<S, ReqBody> Service<HttpRequest<ReqBody>> for CatchPanicService<S>
    where
        S: Service<HttpRequest<ReqBody>, Response = Response> + Clone + Send + 'static,
        S::Future: Send + 'static,
        ReqBody: Send + 'static,
    {
        type Response = S::Response;
        type Error = S::Error;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
            self.service.poll_ready(cx)
        }

        fn call(&mut self, req: HttpRequest<ReqBody>) -> Self::Future {
            let service = self.service.clone();
            let mut service = std::mem::replace(&mut self.service, service);

            Box::pin(async move {
                let path = req.uri().path().to_owned();
                let method = req.method().clone();

                // Оборачиваем вызов сервиса в catch_unwind для перехвата паник
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    service.call(req)
                }));

                match result {
                    Ok(future) => {
                        // Если паники не было, просто возвращаем результат
                        Ok(future.await?)
                    }
                    Err(panic) => {
                        // Если произошла паника, логируем ошибку и возвращаем 500
                        let panic_message = extract_panic_message(panic);
                        error!(
                            "Паника при обработке запроса {} {}: {}",
                            method, path, panic_message
                        );

                        Ok((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ApiResponse::<()>::error(
                                "Внутренняя ошибка сервера. Пожалуйста, попробуйте позже.",
                            )),
                        )
                            .into_response())
                    }
                }
            })
        }
    }

    /// Извлекает сообщение из объекта паники
    fn extract_panic_message(panic: Box<dyn Any + Send>) -> String {
        if let Some(s) = panic.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = panic.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "Неизвестная ошибка".to_string()
        }
    }
}
