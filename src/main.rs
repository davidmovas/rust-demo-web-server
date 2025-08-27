use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use dotenv::dotenv;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::{error, info, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod handlers;
mod middleware;
mod models;
mod routes;
mod services;
mod utils;

use config::AppConfig;
use services::redis_service::{RedisService, RedisServiceError};

/// Состояние приложения, доступное во всех обработчиках
#[derive(Clone)]
pub struct AppState {
    /// Конфигурация приложения
    pub config: Arc<AppConfig>,
    /// Сервис для работы с Redis
    pub redis: RedisService,
}

/// Основная функция приложения
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Загружаем переменные окружения из .env файла
    dotenv().ok();

    // Инициализируем логирование
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Инициализация конфигурации приложения");
    let config = AppConfig::from_env()?;
    let config = Arc::new(config);

    // Инициализируем подключение к Redis
    info!("Инициализация подключения к Redis");
    let redis_service = RedisService::new(&config.redis).await
        .map_err(|e| {
            error!("Не удалось подключиться к Redis: {}", e);
            anyhow::anyhow!("Ошибка подключения к Redis: {}", e)
        })?;

    // Проверяем работоспособность Redis
    if redis_service.health_check().await? {
        info!("Подключение к Redis успешно проверено");
    } else {
        error!("Проверка подключения к Redis не удалась");
        return Err(anyhow::anyhow!("Проверка подключения к Redis не удалась"));
    }

    let app_state = AppState {
        config: config.clone(),
        redis: redis_service,
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));

    let app = create_app(app_state);

    info!("Запуск сервера на {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Сервер остановлен");
    Ok(())
}

/// Создает основной роутер приложения
fn create_app(app_state: AppState) -> Router {
    // Создаем роутер без состояния
    let app = Router::new()
        .layer(TraceLayer::new_for_http());

    // Объединяем с другими роутерами
    let merged_app = app.merge(routes::basic::create_router())
       .merge(routes::api::create_router())
       .merge(routes::auth::create_router())
       .merge(routes::advanced::create_router())
       // Добавляем состояние после объединения всех роутеров
       .with_state(app_state);

    merged_app
}

/// Обработчик сигнала завершения работы
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Не удалось установить обработчик Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Не удалось установить обработчик сигнала завершения")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Получен сигнал завершения, начинаем корректное завершение работы");
}
