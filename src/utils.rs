//! Модуль с утилитами и вспомогательными функциями
//!
//! Содержит различные утилиты, используемые в приложении,
//! такие как функции для работы с паролями, валидации и т.д.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::future::Future;
use thiserror::Error;
use tracing::error;
use validator::Validate;

/// Модуль для работы с паролями
pub mod password {
    use super::*;

    /// Ошибки при работе с паролями
    #[derive(Debug, Error)]
    pub enum PasswordError {
        /// Ошибка хеширования пароля
        #[error("Ошибка хеширования пароля: {0}")]
        HashError(String),

        /// Ошибка проверки пароля
        #[error("Ошибка проверки пароля: {0}")]
        VerificationError(String),

        /// Неверный пароль
        #[error("Неверный пароль")]
        InvalidPassword,
    }

    /// Хеширует пароль с использованием Argon2
    pub fn hash_password(password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| PasswordError::HashError(e.to_string()))
    }

    /// Проверяет соответствие пароля хешу
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| PasswordError::VerificationError(e.to_string()))?;

        let result = Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map(|_| true)
            .map_err(|_| PasswordError::InvalidPassword);

        match result {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false), // Этот случай не должен возникать, но добавлен для полноты
            Err(PasswordError::InvalidPassword) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Модуль для работы с датами и временем
pub mod datetime {
    use super::*;

    /// Форматирует DateTime в строку в формате RFC3339
    pub fn format_datetime(dt: DateTime<Utc>) -> String {
        dt.to_rfc3339()
    }

    /// Добавляет указанное количество секунд к текущему времени
    pub fn add_seconds_to_now(seconds: i64) -> DateTime<Utc> {
        Utc::now() + Duration::seconds(seconds)
    }

    /// Проверяет, истекла ли указанная дата
    pub fn is_expired(dt: DateTime<Utc>) -> bool {
        dt < Utc::now()
    }
}

/// Модуль для валидации данных
pub mod validation {
    use super::*;
    use std::collections::HashMap;
    use validator::ValidationErrors;

    /// Преобразует ошибки валидации в удобный формат
    pub fn format_validation_errors(errors: ValidationErrors) -> HashMap<String, Vec<String>> {
        let mut error_map = HashMap::new();

        for (field, field_errors) in errors.field_errors() {
            let error_messages: Vec<String> = field_errors
                .iter()
                .map(|error| {
                    error
                        .message
                        .clone()
                        .unwrap_or_else(|| "Ошибка валидации".into())
                        .to_string()
                })
                .collect();

            error_map.insert(field.to_string(), error_messages);
        }

        error_map
    }

    /// Валидирует структуру и возвращает отформатированные ошибки
    pub fn validate_struct<T: Validate>(
        data: &T,
    ) -> Result<(), HashMap<String, Vec<String>>> {
        data.validate()
            .map_err(|e| format_validation_errors(e))
    }
}

/// Модуль для работы с асинхронными операциями
pub mod async_utils {
    use super::*;
    use std::time::Duration as StdDuration;
    use tokio::time::sleep;

    /// Выполняет асинхронную операцию с повторными попытками
    pub async fn retry<F, Fut, T, E>(
        operation: F,
        retries: usize,
        delay_ms: u64,
    ) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let mut last_error = None;
        let mut attempts = 0;

        while attempts <= retries {
            match operation().await {
                Ok(value) => return Ok(value),
                Err(e) => {
                    attempts += 1;
                    last_error = Some(e);

                    if attempts <= retries {
                        error!("Попытка {}/{} не удалась, повтор через {} мс", attempts, retries, delay_ms);
                        sleep(StdDuration::from_millis(delay_ms)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }
}

/// Модуль для работы со строками
pub mod string {
    /// Обрезает строку до указанной длины, добавляя многоточие
    pub fn truncate(s: &str, max_length: usize) -> String {
        if s.len() <= max_length {
            s.to_string()
        } else {
            format!("{}...", &s[0..max_length - 3])
        }
    }

    /// Проверяет, содержит ли строка только буквы и цифры
    pub fn is_alphanumeric(s: &str) -> bool {
        s.chars().all(|c| c.is_alphanumeric())
    }

    /// Проверяет, является ли строка валидным именем пользователя
    pub fn is_valid_username(s: &str) -> bool {
        !s.is_empty() && s.len() >= 3 && s.len() <= 30 && is_alphanumeric(s)
    }
}
