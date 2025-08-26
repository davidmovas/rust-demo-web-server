//! Модуль с моделями данных для приложения
//!
//! Содержит структуры данных, используемые в различных частях приложения,
//! включая модели для базы данных, запросов и ответов API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Модуль с моделями пользователей
pub mod user {
    use super::*;

    /// Модель пользователя в базе данных
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct User {
        /// Уникальный идентификатор пользователя
        pub id: Uuid,
        /// Имя пользователя (логин)
        pub username: String,
        /// Email пользователя
        pub email: String,
        /// Хешированный пароль
        #[serde(skip_serializing)]
        pub password_hash: String,
        /// Роль пользователя
        pub role: UserRole,
        /// Дата и время создания записи
        pub created_at: DateTime<Utc>,
        /// Дата и время последнего обновления записи
        pub updated_at: DateTime<Utc>,
    }

    /// Роли пользователей
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub enum UserRole {
        /// Обычный пользователь
        User,
        /// Администратор
        Admin,
    }

    /// Данные для создания нового пользователя
    #[derive(Debug, Deserialize)]
    pub struct CreateUserRequest {
        /// Имя пользователя
        pub username: String,

        /// Email пользователя
        pub email: String,

        /// Пароль пользователя
        pub password: String,
    }

    /// Данные для обновления пользователя
    #[derive(Debug, Deserialize)]
    pub struct UpdateUserRequest {
        /// Имя пользователя (опционально)
        pub username: Option<String>,

        /// Email пользователя (опционально)
        pub email: Option<String>,

        /// Пароль пользователя (опционально)
        pub password: Option<String>,
    }

    /// Данные для ответа с информацией о пользователе
    #[derive(Debug, Serialize)]
    pub struct UserResponse {
        /// Уникальный идентификатор пользователя
        pub id: Uuid,
        /// Имя пользователя
        pub username: String,
        /// Email пользователя
        pub email: String,
        /// Роль пользователя
        pub role: UserRole,
        /// Дата и время создания
        pub created_at: DateTime<Utc>,
    }

    impl From<User> for UserResponse {
        fn from(user: User) -> Self {
            Self {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
                created_at: user.created_at,
            }
        }
    }
}

/// Модуль с моделями для аутентификации
pub mod auth {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Запрос на вход в систему
    #[derive(Debug, Deserialize)]
    pub struct LoginRequest {
        /// Имя пользователя или email
        pub username: String,
        /// Пароль
        pub password: String,
    }

    /// Данные для JWT токена
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Claims {
        /// Идентификатор пользователя (subject)
        pub sub: String,
        /// Время истечения токена (в секундах с начала эпохи Unix)
        pub exp: u64,
        /// Время выдачи токена (в секундах с начала эпохи Unix)
        pub iat: u64,
        /// Роль пользователя
        pub role: String,
    }

    /// Ответ с токеном аутентификации
    #[derive(Debug, Serialize)]
    pub struct TokenResponse {
        /// JWT токен доступа
        pub access_token: String,
        /// Тип токена (всегда "Bearer")
        pub token_type: String,
        /// Время жизни токена в секундах
        pub expires_in: u64,
    }

    impl Claims {
        /// Создает новые claims для JWT токена
        pub fn new(user_id: Uuid, role: &str, expiration_seconds: u64) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Ошибка получения времени")
                .as_secs();

            Self {
                sub: user_id.to_string(),
                exp: now + expiration_seconds,
                iat: now,
                role: role.to_string(),
            }
        }
    }
}

/// Модуль с общими моделями для API
pub mod api {
    use super::*;
    use std::collections::HashMap;

    /// Стандартный ответ API с сообщением
    #[derive(Debug, Serialize)]
    pub struct ApiResponse<T> {
        /// Статус ответа (success/error)
        pub status: ApiStatus,
        /// Сообщение
        pub message: String,
        /// Данные (опционально)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub data: Option<T>,
    }

    /// Статус ответа API
    #[derive(Debug, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum ApiStatus {
        /// Успешный ответ
        Success,
        /// Ответ с ошибкой
        Error,
    }

    /// Ответ с ошибкой валидации
    #[derive(Debug, Serialize)]
    pub struct ValidationErrorResponse {
        /// Статус ответа (всегда error)
        pub status: ApiStatus,
        /// Сообщение об ошибке
        pub message: String,
        /// Ошибки валидации по полям
        pub errors: HashMap<String, Vec<String>>,
    }

    impl<T> ApiResponse<T> {
        /// Создает успешный ответ с данными
        pub fn success(message: impl Into<String>, data: T) -> Self {
            Self {
                status: ApiStatus::Success,
                message: message.into(),
                data: Some(data),
            }
        }

        /// Создает успешный ответ без данных
        pub fn success_message(message: impl Into<String>) -> ApiResponse<()> {
            ApiResponse {
                status: ApiStatus::Success,
                message: message.into(),
                data: None,
            }
        }

        /// Создает ответ с ошибкой
        pub fn error(message: impl Into<String>) -> ApiResponse<()> {
            ApiResponse {
                status: ApiStatus::Error,
                message: message.into(),
                data: None,
            }
        }
    }

    impl ValidationErrorResponse {
        /// Создает ответ с ошибками валидации
        pub fn new(errors: HashMap<String, Vec<String>>) -> Self {
            Self {
                status: ApiStatus::Error,
                message: "Ошибка валидации данных".to_string(),
                errors,
            }
        }
    }
}

/// Модуль с моделями для загрузки файлов
pub mod upload {
    use super::*;

    /// Информация о загруженном файле
    #[derive(Debug, Serialize, Deserialize)]
    pub struct FileInfo {
        /// Уникальный идентификатор файла
        pub id: Uuid,
        /// Оригинальное имя файла
        pub original_filename: String,
        /// Сохраненное имя файла
        pub stored_filename: String,
        /// Размер файла в байтах
        pub size: i64,
        /// MIME-тип файла
        pub content_type: String,
        /// Описание файла
        pub description: Option<String>,
        /// Пользователь, загрузивший файл
        pub user_id: Option<Uuid>,
        /// Дата и время загрузки
        pub uploaded_at: DateTime<Utc>,
    }

    /// Ответ с информацией о загруженном файле
    #[derive(Debug, Serialize)]
    pub struct UploadResponse {
        /// Уникальный идентификатор файла
        pub id: Uuid,
        /// Оригинальное имя файла
        pub filename: String,
        /// Размер файла в байтах
        pub size: i64,
        /// MIME-тип файла
        pub content_type: String,
        /// URL для доступа к файлу
        pub url: String,
    }
}
