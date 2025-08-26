# Демонстрационный веб-сервер на Rust

Этот проект представляет собой демонстрационный веб-сервер, разработанный на языке Rust с использованием современных библиотек и подходов. Сервер включает в себя различные типы эндпоинтов: от простых до сложных, демонстрирующих возможности Rust в веб-разработке.

## Технологии и библиотеки

- **[Axum](https://github.com/tokio-rs/axum)** - современный веб-фреймворк для Rust
- **[Tokio](https://tokio.rs/)** - асинхронный рантайм для Rust
- **[SQLx](https://github.com/launchbadge/sqlx)** - асинхронная библиотека для работы с базами данных
- **[Serde](https://serde.rs/)** - сериализация/десериализация данных
- **[Tracing](https://github.com/tokio-rs/tracing)** - система логирования
- **[JWT](https://github.com/Keats/jsonwebtoken)** - аутентификация с использованием JSON Web Tokens
- **[Argon2](https://github.com/RustCrypto/password-hashes/tree/master/argon2)** - хеширование паролей

## Структура проекта

```
demo-web-server/
├── src/
│   ├── main.rs           - Точка входа в приложение
│   ├── config.rs         - Конфигурация приложения
│   ├── routes.rs         - Маршруты API
│   ├── handlers.rs       - Обработчики запросов
│   ├── models.rs         - Модели данных
│   ├── middleware.rs     - Промежуточные обработчики
│   └── utils.rs          - Вспомогательные функции
├── .env                  - Переменные окружения
├── Cargo.toml            - Зависимости проекта
└── README.md             - Документация
```

## Запуск проекта

### Предварительные требования

- Установленный Rust (https://www.rust-lang.org/tools/install)
- PostgreSQL (опционально, для полноценной работы с базой данных)

### Шаги для запуска

1. Клонировать репозиторий:
   ```bash
   git clone <url-репозитория>
   cd demo-web-server
   ```

2. Настроить переменные окружения (отредактировать файл `.env`):
   ```
   SERVER_PORT=3000
   ENVIRONMENT=development
   DATABASE_URL=postgres://postgres:postgres@localhost:5432/demo_web_server
   JWT_SECRET=your_secret_key
   ```

3. Запустить сервер:
   ```bash
   cargo run
   ```

## API эндпоинты

### Базовые эндпоинты

- `GET /health` - Проверка работоспособности сервера
- `GET /echo?message=hello` - Эхо-сервис, возвращает переданное сообщение
- `GET /echo/:message` - Эхо-сервис с параметром в пути

### API эндпоинты (CRUD)

- `GET /api/users` - Получение списка пользователей
- `GET /api/users/:id` - Получение пользователя по ID
- `POST /api/users` - Создание нового пользователя
- `PUT /api/users/:id` - Обновление пользователя
- `DELETE /api/users/:id` - Удаление пользователя

### Аутентификация

- `POST /auth/login` - Вход в систему (получение JWT токена)
- `POST /auth/register` - Регистрация нового пользователя

### Продвинутые эндпоинты

- `GET /advanced/form` - Отображение HTML формы для загрузки файла
- `POST /advanced/upload` - Загрузка файла

## Примеры запросов

### Регистрация пользователя

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'
```

### Вход в систему

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

### Создание пользователя (с аутентификацией)

```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"username":"newuser","email":"new@example.com","password":"password123"}'
```

## Особенности реализации

- **Асинхронная обработка запросов** - использование async/await для эффективной обработки запросов
- **Типобезопасность** - строгая типизация данных на всех уровнях приложения
- **Обработка ошибок** - корректная обработка и возврат ошибок клиенту
- **Логирование** - подробное логирование действий для отладки
- **Валидация данных** - проверка входных данных перед обработкой
- **Безопасность** - хеширование паролей, JWT аутентификация

## Дальнейшее развитие

- Добавление тестов
- Реализация WebSocket эндпоинтов
- Интеграция с другими базами данных
- Добавление кэширования
- Контейнеризация с использованием Docker