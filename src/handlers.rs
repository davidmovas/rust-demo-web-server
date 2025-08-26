//! Модуль с обработчиками бизнес-логики
//!
//! Содержит функции, реализующие бизнес-логику приложения,
//! отделенную от маршрутизации и представления.

use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    models::{
        api::ApiResponse,
        auth::{Claims, TokenResponse},
        user::{CreateUserRequest, UpdateUserRequest, User, UserResponse, UserRole},
    },
    utils::{
        password::{hash_password, verify_password},
        string::is_valid_username,
    },
};

/// Модуль с обработчиками для пользователей
pub mod users {
    use super::*;

    /// Получает список пользователей
    pub async fn get_users(
        State(config): State<Arc<AppConfig>>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Обработка запроса на получение списка пользователей");

        // В реальном приложении здесь был бы запрос к базе данных
        // Например, с использованием SQLx:
        // let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        //     .fetch_all(&pool)
        //     .await
        //     .map_err(|e| {
        //         error!("Ошибка при получении пользователей: {}", e);
        //         StatusCode::INTERNAL_SERVER_ERROR
        //     })?;

        // Для демонстрации возвращаем тестовые данные
        let users = vec![
            UserResponse {
                id: Uuid::new_v4(),
                username: "user1".to_string(),
                email: "user1@example.com".to_string(),
                role: UserRole::User,
                created_at: Utc::now(),
            },
            UserResponse {
                id: Uuid::new_v4(),
                username: "admin".to_string(),
                email: "admin@example.com".to_string(),
                role: UserRole::Admin,
                created_at: Utc::now(),
            },
        ];

        Ok(Json(ApiResponse::success("Список пользователей получен", users)))
    }

    /// Получает пользователя по ID
    pub async fn get_user_by_id(
        Path(id): Path<Uuid>,
        State(config): State<Arc<AppConfig>>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Обработка запроса на получение пользователя с ID: {}", id);

        // В реальном приложении здесь был бы запрос к базе данных
        // Например:
        // let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        //     .bind(id)
        //     .fetch_optional(&pool)
        //     .await
        //     .map_err(|e| {
        //         error!("Ошибка при получении пользователя: {}", e);
        //         StatusCode::INTERNAL_SERVER_ERROR
        //     })?;
        //
        // if let Some(user) = user {
        //     Ok(Json(ApiResponse::success("Пользователь найден", UserResponse::from(user))))
        // } else {
        //     Err(StatusCode::NOT_FOUND)
        // }

        // Для демонстрации возвращаем тестовые данные
        let user = UserResponse {
            id,
            username: "example_user".to_string(),
            email: "user@example.com".to_string(),
            role: UserRole::User,
            created_at: Utc::now(),
        };

        Ok(Json(ApiResponse::success("Пользователь найден", user)))
    }

    /// Создает нового пользователя
    pub async fn create_user(
        State(config): State<Arc<AppConfig>>,
        Json(payload): Json<CreateUserRequest>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Обработка запроса на создание пользователя");

        // Валидация данных
        if payload.username.len() < 3 || payload.username.len() > 30 {
            error!("Ошибка валидации: имя пользователя должно содержать от 3 до 30 символов");
            return Err(StatusCode::BAD_REQUEST);
        }

        if !is_valid_username(&payload.username) {
            error!("Ошибка валидации: имя пользователя содержит недопустимые символы");
            return Err(StatusCode::BAD_REQUEST);
        }

        if !payload.email.contains('@') {
            error!("Ошибка валидации: некорректный формат email");
            return Err(StatusCode::BAD_REQUEST);
        }

        if payload.password.len() < 8 {
            error!("Ошибка валидации: пароль должен содержать не менее 8 символов");
            return Err(StatusCode::BAD_REQUEST);
        }

        // Хеширование пароля
        let password_hash = hash_password(&payload.password).map_err(|e| {
            error!("Ошибка хеширования пароля: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // В реальном приложении здесь была бы вставка в базу данных
        // Например:
        // let user_id = Uuid::new_v4();
        // let now = Utc::now();
        //
        // let result = sqlx::query(
        //     "INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at)
        //      VALUES ($1, $2, $3, $4, $5, $6, $7)"
        // )
        // .bind(user_id)
        // .bind(&payload.username)
        // .bind(&payload.email)
        // .bind(&password_hash)
        // .bind(UserRole::User)
        // .bind(now)
        // .bind(now)
        // .execute(&pool)
        // .await
        // .map_err(|e| {
        //     error!("Ошибка при создании пользователя: {}", e);
        //     StatusCode::INTERNAL_SERVER_ERROR
        // })?;

        // Для демонстрации создаем тестовые данные
        let user = UserResponse {
            id: Uuid::new_v4(),
            username: payload.username,
            email: payload.email,
            role: UserRole::User,
            created_at: Utc::now(),
        };

        Ok((
            StatusCode::CREATED,
            Json(ApiResponse::success("Пользователь успешно создан", user)),
        ))
    }

    /// Обновляет данные пользователя
    pub async fn update_user(
        Path(id): Path<Uuid>,
        State(config): State<Arc<AppConfig>>,
        Json(payload): Json<UpdateUserRequest>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Обработка запроса на обновление пользователя с ID: {}", id);

        // Валидация данных
        if let Some(username) = &payload.username {
            if username.len() < 3 || username.len() > 30 {
                error!("Ошибка валидации: имя пользователя должно содержать от 3 до 30 символов");
                return Err(StatusCode::BAD_REQUEST);
            }

            if !is_valid_username(username) {
                error!("Ошибка валидации: имя пользователя содержит недопустимые символы");
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        if let Some(email) = &payload.email {
            if !email.contains('@') {
                error!("Ошибка валидации: некорректный формат email");
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        if let Some(password) = &payload.password {
            if password.len() < 8 {
                error!("Ошибка валидации: пароль должен содержать не менее 8 символов");
                return Err(StatusCode::BAD_REQUEST);
            }
        }

        // В реальном приложении здесь было бы обновление в базе данных
        // Например:
        // let mut query_parts = Vec::new();
        // let mut query_index = 1;
        // let mut query = String::from("UPDATE users SET updated_at = $1");
        //
        // let now = Utc::now();
        // let mut bindings: Vec<&(dyn ToSql + Sync)> = vec![&now];
        //
        // if let Some(username) = &payload.username {
        //     query_index += 1;
        //     query_parts.push(format!("username = ${}", query_index));
        //     bindings.push(username);
        // }
        //
        // if let Some(email) = &payload.email {
        //     query_index += 1;
        //     query_parts.push(format!("email = ${}", query_index));
        //     bindings.push(email);
        // }
        //
        // if let Some(password) = &payload.password {
        //     let password_hash = hash_password(password).map_err(|e| {
        //         error!("Ошибка хеширования пароля: {}", e);
        //         StatusCode::INTERNAL_SERVER_ERROR
        //     })?;
        //
        //     query_index += 1;
        //     query_parts.push(format!("password_hash = ${}", query_index));
        //     bindings.push(&password_hash);
        // }
        //
        // if !query_parts.is_empty() {
        //     query.push_str(", ");
        //     query.push_str(&query_parts.join(", "));
        // }
        //
        // query_index += 1;
        // query.push_str(&format!(" WHERE id = ${} RETURNING *", query_index));
        // bindings.push(&id);
        //
        // let user = sqlx::query_as::<_, User>(&query)
        //     .execute(&pool)
        //     .await
        //     .map_err(|e| {
        //         error!("Ошибка при обновлении пользователя: {}", e);
        //         StatusCode::INTERNAL_SERVER_ERROR
        //     })?;

        // Для демонстрации возвращаем тестовые данные
        let user = UserResponse {
            id,
            username: payload.username.unwrap_or_else(|| "updated_user".to_string()),
            email: payload.email.unwrap_or_else(|| "updated@example.com".to_string()),
            role: UserRole::User,
            created_at: Utc::now(),
        };

        Ok(Json(ApiResponse::success(
            "Пользователь успешно обновлен",
            user,
        )))
    }

    /// Удаляет пользователя
    pub async fn delete_user(
        Path(id): Path<Uuid>,
        State(config): State<Arc<AppConfig>>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Обработка запроса на удаление пользователя с ID: {}", id);

        // В реальном приложении здесь было бы удаление из базы данных
        // Например:
        // let result = sqlx::query("DELETE FROM users WHERE id = $1")
        //     .bind(id)
        //     .execute(&pool)
        //     .await
        //     .map_err(|e| {
        //         error!("Ошибка при удалении пользователя: {}", e);
        //         StatusCode::INTERNAL_SERVER_ERROR
        //     })?;
        //
        // if result.rows_affected() == 0 {
        //     return Err(StatusCode::NOT_FOUND);
        // }

        Ok(Json(ApiResponse::<()>::success_message(
            "Пользователь успешно удален",
        )))
    }
}

/// Модуль с обработчиками для аутентификации
pub mod auth {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Структура для запроса логина
    #[derive(Debug, Deserialize)]
    pub struct LoginRequest {
        pub username: String,
        pub password: String,
    }

    /// Выполняет аутентификацию пользователя
    pub async fn login(
        State(config): State<Arc<AppConfig>>,
        Json(payload): Json<LoginRequest>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Обработка запроса на аутентификацию пользователя: {}", payload.username);

        // В реальном приложении здесь была бы проверка учетных данных в базе
        // Например:
        // let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1 OR email = $1")
        //     .bind(&payload.username)
        //     .fetch_optional(&pool)
        //     .await
        //     .map_err(|e| {
        //         error!("Ошибка при поиске пользователя: {}", e);
        //         StatusCode::INTERNAL_SERVER_ERROR
        //     })?;
        //
        // let user = user.ok_or(StatusCode::UNAUTHORIZED)?;
        //
        // let is_valid = verify_password(&payload.password, &user.password_hash)
        //     .map_err(|e| {
        //         error!("Ошибка при проверке пароля: {}", e);
        //         StatusCode::INTERNAL_SERVER_ERROR
        //     })?;
        //
        // if !is_valid {
        //     return Err(StatusCode::UNAUTHORIZED);
        // }

        // Для демонстрации проверяем фиксированные учетные данные
        if payload.username != "admin" || payload.password != "password" {
            return Err(StatusCode::UNAUTHORIZED);
        }

        // Создаем JWT токен
        let expiration = config.jwt.expiration * 60; // конвертируем минуты в секунды
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Ошибка получения времени")
            .as_secs();

        let claims = Claims::new(
            Uuid::new_v4(), // В реальном приложении здесь был бы ID пользователя из БД
            "admin",        // В реальном приложении здесь была бы роль из БД
            expiration,
        );

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt.secret.as_bytes()),
        )
        .map_err(|e| {
            error!("Ошибка создания JWT токена: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let response = TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: expiration,
        };

        Ok(Json(ApiResponse::success(
            "Аутентификация успешна",
            response,
        )))
    }

    /// Регистрирует нового пользователя
    pub async fn register(
        State(config): State<Arc<AppConfig>>,
        Json(payload): Json<CreateUserRequest>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Обработка запроса на регистрацию пользователя: {}", payload.username);

        // Валидация данных
        if payload.username.len() < 3 || payload.username.len() > 30 {
            error!("Ошибка валидации: имя пользователя должно содержать от 3 до 30 символов");
            return Err(StatusCode::BAD_REQUEST);
        }

        if !is_valid_username(&payload.username) {
            error!("Ошибка валидации: имя пользователя содержит недопустимые символы");
            return Err(StatusCode::BAD_REQUEST);
        }

        if !payload.email.contains('@') {
            error!("Ошибка валидации: некорректный формат email");
            return Err(StatusCode::BAD_REQUEST);
        }

        if payload.password.len() < 8 {
            error!("Ошибка валидации: пароль должен содержать не менее 8 символов");
            return Err(StatusCode::BAD_REQUEST);
        }

        // В реальном приложении здесь была бы проверка на существование пользователя
        // и сохранение в базу данных (аналогично create_user)

        // Создаем JWT токен
        let expiration = config.jwt.expiration * 60;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Ошибка получения времени")
            .as_secs();

        let claims = Claims::new(
            Uuid::new_v4(),
            "user",
            expiration,
        );

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt.secret.as_bytes()),
        )
        .map_err(|e| {
            error!("Ошибка создания JWT токена: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let response = TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: expiration,
        };

        Ok((
            StatusCode::CREATED,
            Json(ApiResponse::success("Регистрация успешна", response)),
        ))
    }
}
