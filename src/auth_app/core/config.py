from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Демо авторизации: session и JWT"
    database_url: str = Field(default="postgresql+asyncpg://postgres:postgres@localhost:5432/postgres", alias="DATABASE_URL")
    jwt_secret_key: str = Field(default="change-me", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = "HS256"
    access_token_expires_minutes: int = 15
    refresh_token_expires_minutes: int = 60 * 24 * 30
    session_ttl_minutes: int = 60 * 24
    session_extend_minutes: int = 60 * 24 * 7
    session_rolling_interval_minutes: int = 10
    session_cookie_name: str = "session_id"
    session_cookie_secure: bool = False
    session_cookie_domain: str | None = None
    access_cookie_name: str = "access_token"
    refresh_cookie_name: str = "refresh_token"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore")


settings = Settings()
