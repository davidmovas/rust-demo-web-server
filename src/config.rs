use serde::Deserialize;
use std::env;
use anyhow::Result;

/// Основная конфигурация приложения
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// Конфигурация сервера
    pub server: ServerConfig,
    /// Конфигурация Redis
    pub redis: RedisConfig,
    /// Конфигурация JWT токенов
    pub jwt: JwtConfig,
}

/// Конфигурация веб-сервера
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Порт, на котором запускается сервер
    pub port: u16,
    /// Режим работы (development, production)
    pub environment: Environment,
}

/// Конфигурация Redis
#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// URL подключения к Redis
    pub url: String,
    /// Максимальное количество соединений в пуле
    pub max_connections: u32,
}

/// Конфигурация JWT токенов
#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// Секретный ключ для подписи токенов
    pub secret: String,
    /// Время жизни токена в минутах
    pub expiration: u64,
}

/// Режимы работы приложения
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Production,
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Development
    }
}

impl AppConfig {
    /// Создает конфигурацию из переменных окружения
    pub fn from_env() -> Result<Self> {
        // Настройки сервера
        let port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()?;
            
        let environment = match env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()).as_str() {
            "production" => Environment::Production,
            _ => Environment::Development,
        };

        // Настройки Redis
        let redis_url = env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:16797".to_string());
            
        let redis_max_connections = env::var("REDIS_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()?;

        // Настройки JWT
        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "super_secret_key_change_in_production".to_string());
            
        let jwt_expiration = env::var("JWT_EXPIRATION")
            .unwrap_or_else(|_| "60".to_string()) // 60 минут по умолчанию
            .parse::<u64>()?;

        Ok(AppConfig {
            server: ServerConfig {
                port,
                environment,
            },
            redis: RedisConfig {
                url: redis_url,
                max_connections: redis_max_connections,
            },
            jwt: JwtConfig {
                secret: jwt_secret,
                expiration: jwt_expiration,
            },
        })
    }

    /// Проверяет, запущено ли приложение в режиме разработки
    pub fn is_development(&self) -> bool {
        self.server.environment == Environment::Development
    }

    /// Проверяет, запущено ли приложение в производственном режиме
    pub fn is_production(&self) -> bool {
        self.server.environment == Environment::Production
    }
}