# Демо авторизации: session и JWT

Приложение на FastAPI (концепция не привязана к фреймворку) демонстрирует регистрацию, вход/выход и работу через сессионные куки и JWT access + refresh. Стек: async SQLAlchemy, PostgreSQL 17, uvicorn.

## Что есть
- Таблицы `users` (id, name, password_hash) и `sessions` (hash токена, срок действия) в PostgreSQL.
- Сессионная авторизация с http-only cookie, хранением хэша токена и очисткой просроченных сессий.
- JWT авторизация с access токенами на `pyjwt`; refresh — непрозрачные строки, в БД хранится только SHA-256 хэш. Оба токена дополнительно кладутся в куки (`access_token`, `refresh_token`).
- Асинхронный стек: FastAPI, SQLAlchemy 2.x + asyncpg, uvicorn.
- Docker Compose поднимает PostgreSQL 17 и API.

## Подготовка окружения
1. Установите `uv` (через `pip install uv` или скрипт https://astral.sh/uv).
2. Поднимите Postgres 17 (по умолчанию пользователь/пароль/база — `postgres`).
3. Создайте `.env` с нужными значениями (см. список переменных ниже). По умолчанию `DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:7432/postgres`.

## Локальный запуск (API + отдельный Postgres)
```bash
uv sync
docker compose up -d db  # поднимет только Postgres
uv run uvicorn auth_app.main:app --reload --host 0.0.0.0 --port 8000
```
API будет на `http://localhost:8000`, swagger UI — `/docs`.
Фронтенд-демо доступно на корне (`/`) и ходит к API с этого же хоста.

## Запуск целиком через Docker Compose
Compose поднимет API и PostgreSQL в одном `docker compose up` (API смотрит на хост `db` через переменную окружения, прокидываемую внутри композа).
```bash
docker compose up --build
```
После старта API доступен на `http://localhost:8000`, UI swagger — `/docs`, статический демо-фронт — `/`.

## Основные переменные окружения
- `DATABASE_URL` (default `postgresql+asyncpg://postgres:postgres@localhost:7432/postgres`)
- `JWT_SECRET_KEY` — секрет для подписи JWT
- `ACCESS_TOKEN_EXPIRES_MINUTES` (по умолчанию 15)
- `REFRESH_TOKEN_EXPIRES_MINUTES` (по умолчанию 43200, то есть 30 дней)
- `SESSION_TTL_MINUTES` (по умолчанию 1440)
- `SESSION_EXTEND_MINUTES` (rolling продление, по умолчанию 10080 = 7 дней)
- `SESSION_ROLLING_INTERVAL_MINUTES` (интервал проверки для продления, по умолчанию 10)
- `SESSION_COOKIE_NAME`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_DOMAIN`
- `ACCESS_COOKIE_NAME`, `REFRESH_COOKIE_NAME` (по умолчанию `access_token` / `refresh_token`)

## Маршруты
- `POST /auth/register` — регистрация
- `POST /auth/login/session` — логин, установка сессионной куки
- `POST /auth/logout/session` — логаут, очистка куки и записи в БД
- `GET /auth/me/session` — профиль по сессии
- `POST /auth/login/jwt` — логин, выдача пары access/refresh (refresh записывается в БД, хранится хэш)
- `POST /auth/token/refresh` — обновление пары по refresh (старый refresh гасится и заменяется новым)
- `GET /auth/me/jwt` — профиль по access токену

## Примеры запросов
```bash
# регистрация
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"alice","password":"secret"}'

# вход по сессии (cookie сохранится в cookies.txt)
curl -i -c cookies.txt -X POST http://localhost:8000/auth/login/session \
  -H "Content-Type: application/json" \
  -d '{"name":"alice","password":"secret"}'

# доступ с сессией
curl -b cookies.txt http://localhost:8000/auth/me/session

# выход из сессии
curl -b cookies.txt -X POST http://localhost:8000/auth/logout/session

# вход по JWT
TOKENS=$(curl -s -X POST http://localhost:8000/auth/login/jwt \
  -H "Content-Type: application/json" \
  -d '{"name":"alice","password":"secret"}')
ACCESS=$(echo "$TOKENS" | python -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
REFRESH=$(echo "$TOKENS" | python -c "import json,sys;print(json.load(sys.stdin)['refresh_token'])")

# доступ с access токеном
curl -H "Authorization: Bearer $ACCESS" http://localhost:8000/auth/me/jwt

# обновление токенов
curl -X POST http://localhost:8000/auth/token/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```

При старте приложения таблицы создаются автоматически. Пароли хэшируются через bcrypt, сессионные токены сохраняются только в виде SHA-256 хэшей.
