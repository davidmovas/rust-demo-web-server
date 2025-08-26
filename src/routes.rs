//! Модуль маршрутизации для веб-сервера
//! 
//! Этот модуль содержит все маршруты (endpoints) веб-сервера,
//! организованные по уровням сложности и функциональности.

use axum::{
    Router,
    routing::{get, post},
    extract::{Path, Query, Json, Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use crate::AppState;

/// Модуль с базовыми эндпоинтами (echo, health check)
pub mod basic {
    use super::*;

    /// Создает роутер с базовыми эндпоинтами
    pub fn create_router() -> Router<AppState> {
        Router::new()
            .route("/health", get(health_check))
            .route("/echo", get(echo))
            .route("/echo/:message", get(echo_path))
    }

    /// Простой эндпоинт для проверки работоспособности сервера
    async fn health_check() -> impl IntoResponse {
        info!("Запрос к эндпоинту health check");
        StatusCode::OK
    }

    /// Структура для параметров запроса echo
    #[derive(Debug, Deserialize)]
    struct EchoParams {
        message: Option<String>,
    }

    /// Структура для ответа echo
    #[derive(Debug, Serialize)]
    struct EchoResponse {
        message: String,
        timestamp: String,
    }

    /// Эндпоинт echo, возвращающий сообщение из query параметра
    async fn echo(Query(params): Query<EchoParams>) -> impl IntoResponse {
        let message = params.message.unwrap_or_else(|| "Привет, мир!".to_string());
        info!("Запрос к эндпоинту echo с сообщением: {}", message);

        let timestamp = chrono::Local::now().to_rfc3339();

        Json(EchoResponse {
            message,
            timestamp,
        })
    }

    /// Эндпоинт echo, возвращающий сообщение из path параметра
    async fn echo_path(Path(message): Path<String>) -> impl IntoResponse {
        info!("Запрос к эндпоинту echo_path с сообщением: {}", message);

        let timestamp = chrono::Local::now().to_rfc3339();

        Json(EchoResponse {
            message,
            timestamp,
        })
    }
}

/// Модуль с API эндпоинтами (CRUD операции)
pub mod api {
    use super::*;
    use crate::AppState;
    use std::sync::Arc;
    use uuid::Uuid;

    /// Создает роутер с API эндпоинтами
    pub fn create_router() -> Router<AppState> {
        Router::new()
            .route("/api/users", get(get_users).post(create_user))
            .route("/api/users/:id", get(get_user_by_id).put(update_user).delete(delete_user))
    }

    /// Модель пользователя
    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct User {
        id: Option<String>,
        username: String,
        email: String,
        created_at: Option<String>,
    }

    /// Структура для создания пользователя
    #[derive(Debug, Deserialize)]
    struct CreateUserRequest {
        username: String,
        email: String,
    }

    /// Получение списка пользователей
    async fn get_users(State(app_state): State<AppState>) -> impl IntoResponse {
        info!("Запрос на получение списка пользователей");

        // Пытаемся получить список пользователей из Redis
        let users_key = "users:list";
        let users_result: Result<Option<Vec<User>>, _> = app_state.redis.get(users_key).await;

        let users = match users_result {
            Ok(Some(users)) => {
                info!("Получен список пользователей из Redis");
                users
            },
            Ok(None) => {
                info!("Список пользователей не найден в Redis, создаем тестовые данные");
                // Создаем тестовые данные
                let users = vec![
                    User {
                        id: Some("1".to_string()),
                        username: "user1".to_string(),
                        email: "user1@example.com".to_string(),
                        created_at: Some(chrono::Local::now().to_rfc3339()),
                    },
                    User {
                        id: Some("2".to_string()),
                        username: "user2".to_string(),
                        email: "user2@example.com".to_string(),
                        created_at: Some(chrono::Local::now().to_rfc3339()),
                    },
                ];

                // Сохраняем в Redis для будущих запросов
                if let Err(e) = app_state.redis.set(users_key, &users, Some(3600)).await {
                    error!("Ошибка сохранения списка пользователей в Redis: {}", e);
                }

                users
            },
            Err(e) => {
                error!("Ошибка получения списка пользователей из Redis: {}", e);
                // Возвращаем тестовые данные в случае ошибки
                vec![
                    User {
                        id: Some("1".to_string()),
                        username: "user1".to_string(),
                        email: "user1@example.com".to_string(),
                        created_at: Some(chrono::Local::now().to_rfc3339()),
                    },
                    User {
                        id: Some("2".to_string()),
                        username: "user2".to_string(),
                        email: "user2@example.com".to_string(),
                        created_at: Some(chrono::Local::now().to_rfc3339()),
                    },
                ]
            }
        };

        Json(users)
    }

    /// Получение пользователя по ID
    async fn get_user_by_id(
        Path(id): Path<String>,
        State(app_state): State<AppState>
    ) -> impl IntoResponse {
        info!("Запрос на получение пользователя с ID: {}", id);

        // Пытаемся получить пользователя из Redis
        let user_key = format!("users:{}", id);
        let user_result: Result<Option<User>, _> = app_state.redis.get(&user_key).await;

        let user = match user_result {
            Ok(Some(user)) => {
                info!("Получен пользователь из Redis");
                user
            },
            Ok(None) => {
                info!("Пользователь не найден в Redis, создаем тестовые данные");
                // Создаем тестовые данные
                let user = User {
                    id: Some(id.clone()),
                    username: "example_user".to_string(),
                    email: "user@example.com".to_string(),
                    created_at: Some(chrono::Local::now().to_rfc3339()),
                };

                // Сохраняем в Redis для будущих запросов
                if let Err(e) = app_state.redis.set(&user_key, &user, Some(3600)).await {
                    error!("Ошибка сохранения пользователя в Redis: {}", e);
                }

                user
            },
            Err(e) => {
                error!("Ошибка получения пользователя из Redis: {}", e);
                // Возвращаем тестовые данные в случае ошибки
                User {
                    id: Some(id),
                    username: "example_user".to_string(),
                    email: "user@example.com".to_string(),
                    created_at: Some(chrono::Local::now().to_rfc3339()),
                }
            }
        };

        Json(user)
    }

    /// Создание нового пользователя
    async fn create_user(
        State(app_state): State<AppState>,
        Json(payload): Json<CreateUserRequest>,
    ) -> impl IntoResponse {
        info!("Запрос на создание пользователя: {:?}", payload);

        // Создаем нового пользователя
        let user_id = uuid::Uuid::new_v4().to_string();
        let user = User {
            id: Some(user_id.clone()),
            username: payload.username,
            email: payload.email,
            created_at: Some(chrono::Local::now().to_rfc3339()),
        };

        // Сохраняем пользователя в Redis
        let user_key = format!("users:{}", user_id);
        if let Err(e) = app_state.redis.set(&user_key, &user, Some(3600)).await {
            error!("Ошибка сохранения пользователя в Redis: {}", e);
        } else {
            info!("Пользователь успешно сохранен в Redis");

            // Обновляем список пользователей
            let users_key = "users:list";
            let users_result: Result<Option<Vec<User>>, _> = app_state.redis.get(users_key).await;

            match users_result {
                Ok(Some(mut users)) => {
                    // Добавляем нового пользователя в список
                    users.push(user.clone());
                    if let Err(e) = app_state.redis.set(users_key, &users, Some(3600)).await {
                        error!("Ошибка обновления списка пользователей в Redis: {}", e);
                    }
                },
                Ok(None) | Err(_) => {
                    // Создаем новый список с одним пользователем
                    let users = vec![user.clone()];
                    if let Err(e) = app_state.redis.set(users_key, &users, Some(3600)).await {
                        error!("Ошибка создания списка пользователей в Redis: {}", e);
                    }
                }
            }
        }

        (StatusCode::CREATED, Json(user))
    }

    /// Обновление пользователя
    async fn update_user(
        Path(id): Path<String>,
        State(app_state): State<AppState>,
        Json(payload): Json<CreateUserRequest>,
    ) -> impl IntoResponse {
        info!("Запрос на обновление пользователя с ID {}: {:?}", id, payload);

        // Ключ для пользователя в Redis
        let user_key = format!("users:{}", id);

        // Проверяем, существует ли пользователь
        let user_exists = match app_state.redis.exists(&user_key).await {
            Ok(exists) => exists,
            Err(e) => {
                error!("Ошибка проверки существования пользователя в Redis: {}", e);
                false
            }
        };

        // Создаем или обновляем пользователя
        let user = User {
            id: Some(id.clone()),
            username: payload.username,
            email: payload.email,
            created_at: Some(chrono::Local::now().to_rfc3339()),
        };

        // Сохраняем пользователя в Redis
        if let Err(e) = app_state.redis.set(&user_key, &user, Some(3600)).await {
            error!("Ошибка сохранения пользователя в Redis: {}", e);
        } else {
            info!("Пользователь успешно обновлен в Redis");

            // Если пользователь не существовал, добавляем его в список
            if !user_exists {
                let users_key = "users:list";
                let users_result: Result<Option<Vec<User>>, _> = app_state.redis.get(users_key).await;

                match users_result {
                    Ok(Some(mut users)) => {
                        // Добавляем пользователя в список
                        users.push(user.clone());
                        if let Err(e) = app_state.redis.set(users_key, &users, Some(3600)).await {
                            error!("Ошибка обновления списка пользователей в Redis: {}", e);
                        }
                    },
                    Ok(None) | Err(_) => {
                        // Создаем новый список с одним пользователем
                        let users = vec![user.clone()];
                        if let Err(e) = app_state.redis.set(users_key, &users, Some(3600)).await {
                            error!("Ошибка создания списка пользователей в Redis: {}", e);
                        }
                    }
                }
            } else {
                // Если пользователь существовал, обновляем его в списке
                let users_key = "users:list";
                let users_result: Result<Option<Vec<User>>, _> = app_state.redis.get(users_key).await;

                if let Ok(Some(mut users)) = users_result {
                    // Находим и обновляем пользователя в списке
                    if let Some(index) = users.iter().position(|u| u.id.as_ref() == Some(&id)) {
                        users[index] = user.clone();
                        if let Err(e) = app_state.redis.set(users_key, &users, Some(3600)).await {
                            error!("Ошибка обновления списка пользователей в Redis: {}", e);
                        }
                    }
                }
            }
        }

        Json(user)
    }

    /// Удаление пользователя
    async fn delete_user(
        Path(id): Path<String>,
        State(app_state): State<AppState>
    ) -> impl IntoResponse {
        info!("Запрос на удаление пользователя с ID: {}", id);

        // Ключ для пользователя в Redis
        let user_key = format!("users:{}", id);

        // Удаляем пользователя из Redis
        match app_state.redis.delete(&user_key).await {
            Ok(true) => {
                info!("Пользователь успешно удален из Redis");

                // Удаляем пользователя из списка
                let users_key = "users:list";
                let users_result: Result<Option<Vec<User>>, _> = app_state.redis.get(users_key).await;

                if let Ok(Some(mut users)) = users_result {
                    // Находим и удаляем пользователя из списка
                    if let Some(index) = users.iter().position(|u| u.id.as_ref() == Some(&id)) {
                        users.remove(index);
                        if let Err(e) = app_state.redis.set(users_key, &users, Some(3600)).await {
                            error!("Ошибка обновления списка пользователей в Redis после удаления: {}", e);
                        }
                    }
                }
            },
            Ok(false) => {
                info!("Пользователь с ID {} не найден в Redis", id);
            },
            Err(e) => {
                error!("Ошибка удаления пользователя из Redis: {}", e);
            }
        }

        StatusCode::NO_CONTENT
    }
}

/// Модуль с эндпоинтами аутентификации и авторизации
pub mod auth {
    use super::*;
    use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Создает роутер с эндпоинтами аутентификации
    pub fn create_router() -> Router<AppState> {
        Router::new()
            .route("/auth/login", post(login))
            .route("/auth/register", post(register))
    }

    /// Структура для запроса логина
    #[derive(Debug, Deserialize)]
    struct LoginRequest {
        username: String,
        password: String,
    }

    /// Структура для запроса регистрации
    #[derive(Debug, Deserialize)]
    struct RegisterRequest {
        username: String,
        email: String,
        password: String,
    }

    /// Структура для JWT claims
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: u64,
        role: String,
    }

    /// Структура для ответа с токеном
    #[derive(Debug, Serialize)]
    struct TokenResponse {
        access_token: String,
        token_type: String,
        expires_in: u64,
    }

    /// Эндпоинт для логина пользователя
    async fn login(
        Json(payload): Json<LoginRequest>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Запрос на логин пользователя: {}", payload.username);

        // В реальном приложении здесь была бы проверка учетных данных в базе
        // и хеширование пароля
        if payload.username != "admin" || payload.password != "password" {
            return Err(StatusCode::UNAUTHORIZED);
        }

        // Создаем JWT токен
        let expiration = 60 * 60; // 1 час в секундах
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Ошибка получения времени")
            .as_secs();

        let claims = Claims {
            sub: payload.username,
            exp: now + expiration,
            role: "user".to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("super_secret_key_change_in_production".as_bytes()),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let response = TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: expiration,
        };

        Ok(Json(response))
    }

    /// Эндпоинт для регистрации пользователя
    async fn register(
        Json(payload): Json<RegisterRequest>,
    ) -> Result<impl IntoResponse, StatusCode> {
        info!("Запрос на регистрацию пользователя: {}", payload.username);

        // В реальном приложении здесь была бы проверка на существование пользователя,
        // хеширование пароля и сохранение в базу данных

        // Создаем JWT токен
        let expiration = 60 * 60; // 1 час в секундах
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Ошибка получения времени")
            .as_secs();

        let claims = Claims {
            sub: payload.username,
            exp: now + expiration,
            role: "user".to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("super_secret_key_change_in_production".as_bytes()),
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let response = TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: expiration,
        };

        Ok((StatusCode::CREATED, Json(response)))
    }
}

/// Модуль с продвинутыми эндпоинтами
pub mod advanced {
    use super::*;
    use axum::extract::multipart::Field;
    use axum::response::Html;
    use std::path::Path;
    use tokio::fs::{self, File};
    use tokio::io::AsyncWriteExt;
    use uuid::Uuid;

    /// Создает роутер с продвинутыми эндпоинтами
    pub fn create_router() -> Router<AppState> {
        Router::new()
            .route("/advanced/upload", post(upload_file))
            .route("/advanced/form", get(show_form))
    }

    /// Показывает HTML форму для загрузки файла
    async fn show_form() -> impl IntoResponse {
        info!("Запрос на отображение формы загрузки файла");

        Html(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Загрузка файла</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }
                form {
                    border: 1px solid #ddd;
                    padding: 20px;
                    border-radius: 5px;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                }
                button {
                    background-color: #4CAF50;
                    color: white;
                    padding: 10px 15px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }
                button:hover {
                    background-color: #45a049;
                }
            </style>
        </head>
        <body>
            <h1>Загрузка файла</h1>
            <form action="/advanced/upload" method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="file">Выберите файл:</label>
                    <input type="file" id="file" name="file" required>
                </div>
                <div class="form-group">
                    <label for="description">Описание:</label>
                    <textarea id="description" name="description" rows="4" cols="50"></textarea>
                </div>
                <button type="submit">Загрузить</button>
            </form>
        </body>
        </html>
        "#)
    }

    /// Структура для ответа о загруженном файле
    #[derive(Debug, Serialize)]
    struct UploadResponse {
        filename: String,
        size: u64,
        content_type: Option<String>,
        description: Option<String>,
    }

    /// Обрабатывает загрузку файла
    async fn upload_file(mut multipart: Multipart) -> Result<impl IntoResponse, StatusCode> {
        info!("Запрос на загрузку файла");

        let mut filename = String::new();
        let mut size = 0;
        let mut content_type = None;
        let mut description = None;

        // Создаем директорию для загрузок, если она не существует
        let upload_dir = "uploads";
        if !Path::new(upload_dir).exists() {
            fs::create_dir_all(upload_dir)
                .await
                .map_err(|e| {
                    error!("Ошибка создания директории для загрузок: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
        }

        // Обрабатываем части multipart формы
        while let Some(mut field) = multipart.next_field().await.map_err(|e| {
            error!("Ошибка получения поля из multipart формы: {}", e);
            StatusCode::BAD_REQUEST
        })? {
            let name = field.name().unwrap_or("").to_string();

            match name.as_str() {
                "file" => {
                    // Обрабатываем загруженный файл
                    let original_filename = field.file_name().unwrap_or("unknown").to_string();
                    content_type = field.content_type().map(|ct| ct.to_string());

                    // Генерируем уникальное имя файла
                    let uuid = Uuid::new_v4();
                    let extension = Path::new(&original_filename)
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .unwrap_or("");

                    filename = format!("{}.{}", uuid, extension);
                    let path = format!("{}/{}", upload_dir, filename);

                    // Создаем файл для записи
                    let mut file = File::create(&path).await.map_err(|e| {
                        error!("Ошибка создания файла: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    // Потоковая запись данных в файл
                    let mut field_size: u64 = 0;

                    // Читаем данные из поля по частям и записываем в файл
                    while let Some(chunk) = field.chunk().await.map_err(|e| {
                        error!("Ошибка чтения части файла: {}", e);
                        StatusCode::BAD_REQUEST
                    })? {
                        // Увеличиваем счетчик размера
                        field_size += chunk.len() as u64;

                        // Записываем часть в файл
                        file.write_all(&chunk).await.map_err(|e| {
                            error!("Ошибка записи части файла: {}", e);
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;
                    }

                    // Закрываем файл
                    file.flush().await.map_err(|e| {
                        error!("Ошибка закрытия файла: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    size = field_size;
                    info!("Файл сохранен: {}, размер: {} байт", path, size);
                },
                "description" => {
                    // Получаем описание файла
                    description = Some(field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?);
                },
                _ => {
                    // Игнорируем неизвестные поля
                }
            }
        }

        if filename.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }

        let response = UploadResponse {
            filename,
            size,
            content_type,
            description,
        };

        Ok((StatusCode::CREATED, Json(response)))
    }
}
