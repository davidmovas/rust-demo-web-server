//! Сервис для работы с Redis
//!
//! Предоставляет функции для работы с Redis, включая подключение и выполнение операций

use std::sync::Arc;
use redis::{Client, RedisError, RedisResult, aio::ConnectionManager};
use tracing::{error, info};
use crate::config::RedisConfig;

/// Ошибки при работе с Redis
#[derive(Debug, thiserror::Error)]
pub enum RedisServiceError {
    /// Ошибка подключения к Redis
    #[error("Ошибка подключения к Redis: {0}")]
    ConnectionError(#[from] RedisError),

    /// Ошибка выполнения команды
    #[error("Ошибка выполнения команды: {0}")]
    CommandError(String),

    /// Ошибка сериализации/десериализации
    #[error("Ошибка сериализации/десериализации: {0}")]
    SerializationError(String),
}

/// Результат операции с Redis
pub type RedisServiceResult<T> = Result<T, RedisServiceError>;

/// Сервис для работы с Redis
#[derive(Clone)]
pub struct RedisService {
    /// Менеджер подключений к Redis
    connection_manager: ConnectionManager,
}

impl RedisService {
    /// Создает новый экземпляр сервиса Redis
    pub async fn new(config: &RedisConfig) -> RedisServiceResult<Self> {
        let client = Client::open(config.url.clone())
            .map_err(|e| {
                error!("Ошибка создания клиента Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        let connection_manager = ConnectionManager::new(client)
            .await
            .map_err(|e| {
                error!("Ошибка создания менеджера подключений Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        info!("Подключение к Redis успешно установлено");

        Ok(Self {
            connection_manager,
        })
    }

    /// Получает значение по ключу
    pub async fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> RedisServiceResult<Option<T>> {
        let value: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut self.connection_manager.clone())
            .await
            .map_err(|e| {
                error!("Ошибка получения значения из Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        match value {
            Some(val) => {
                serde_json::from_str(&val)
                    .map_err(|e| {
                        error!("Ошибка десериализации значения из Redis: {}", e);
                        RedisServiceError::SerializationError(e.to_string())
                    })
                    .map(Some)
            },
            None => Ok(None),
        }
    }

    /// Устанавливает значение по ключу
    pub async fn set<T: serde::Serialize>(&self, key: &str, value: &T, expiry_seconds: Option<usize>) -> RedisServiceResult<()> {
        let serialized = serde_json::to_string(value)
            .map_err(|e| {
                error!("Ошибка сериализации значения для Redis: {}", e);
                RedisServiceError::SerializationError(e.to_string())
            })?;

        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg(serialized);

        if let Some(expiry) = expiry_seconds {
            cmd.arg("EX").arg(expiry);
        }

        cmd.query_async(&mut self.connection_manager.clone())
            .await
            .map_err(|e| {
                error!("Ошибка установки значения в Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        Ok(())
    }

    /// Удаляет значение по ключу
    pub async fn delete(&self, key: &str) -> RedisServiceResult<bool> {
        let result: i32 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut self.connection_manager.clone())
            .await
            .map_err(|e| {
                error!("Ошибка удаления значения из Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        Ok(result > 0)
    }

    /// Проверяет существование ключа
    pub async fn exists(&self, key: &str) -> RedisServiceResult<bool> {
        let result: i32 = redis::cmd("EXISTS")
            .arg(key)
            .query_async(&mut self.connection_manager.clone())
            .await
            .map_err(|e| {
                error!("Ошибка проверки существования ключа в Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        Ok(result > 0)
    }

    /// Устанавливает время жизни ключа
    pub async fn expire(&self, key: &str, seconds: usize) -> RedisServiceResult<bool> {
        let result: i32 = redis::cmd("EXPIRE")
            .arg(key)
            .arg(seconds)
            .query_async(&mut self.connection_manager.clone())
            .await
            .map_err(|e| {
                error!("Ошибка установки времени жизни ключа в Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        Ok(result > 0)
    }

    /// Получает хеш-значение по ключу и полю
    pub async fn hget<T: serde::de::DeserializeOwned>(&self, key: &str, field: &str) -> RedisServiceResult<Option<T>> {
        let value: Option<String> = redis::cmd("HGET")
            .arg(key)
            .arg(field)
            .query_async(&mut self.connection_manager.clone())
            .await
            .map_err(|e| {
                error!("Ошибка получения хеш-значения из Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        match value {
            Some(val) => {
                serde_json::from_str(&val)
                    .map_err(|e| {
                        error!("Ошибка десериализации хеш-значения из Redis: {}", e);
                        RedisServiceError::SerializationError(e.to_string())
                    })
                    .map(Some)
            },
            None => Ok(None),
        }
    }

    /// Устанавливает хеш-значение по ключу и полю
    pub async fn hset<T: serde::Serialize>(&self, key: &str, field: &str, value: &T) -> RedisServiceResult<()> {
        let serialized = serde_json::to_string(value)
            .map_err(|e| {
                error!("Ошибка сериализации хеш-значения для Redis: {}", e);
                RedisServiceError::SerializationError(e.to_string())
            })?;

        redis::cmd("HSET")
            .arg(key)
            .arg(field)
            .arg(serialized)
            .query_async(&mut self.connection_manager.clone())
            .await
            .map_err(|e| {
                error!("Ошибка установки хеш-значения в Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        Ok(())
    }

    /// Проверяет работоспособность Redis
    pub async fn health_check(&self) -> RedisServiceResult<bool> {
        let result: String = redis::cmd("PING")
            .query_async(&mut self.connection_manager.clone())
            .await
            .map_err(|e| {
                error!("Ошибка проверки работоспособности Redis: {}", e);
                RedisServiceError::ConnectionError(e)
            })?;

        Ok(result == "PONG")
    }
}
