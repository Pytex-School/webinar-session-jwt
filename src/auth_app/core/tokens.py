import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from auth_app.core.config import settings


class TokenHelper:
    def generate_session_token(self) -> tuple[str, str]:
        """Создает сессионный токен и возвращает пару (сырой, хэш)."""
        token = secrets.token_urlsafe(32)
        return token, self.hash_session_token(token)

    def hash_session_token(self, token: str) -> str:
        """Хэширует сессионный токен через SHA-256."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_access_token(self, user_id: int) -> str:
        """Формирует JWT access c типом access и истечением из настроек."""
        return self._create_token(user_id, "access", settings.access_token_expires_minutes)

    def create_refresh_token(self) -> str:
        """Создает долгоживущий случайный refresh токен (не JWT)."""
        return secrets.token_urlsafe(48)

    def decode_token(self, token: str, expected_type: str) -> dict:
        """Декодирует JWT и проверяет совпадение типа."""
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        if payload.get("type") != expected_type:
            raise jwt.InvalidTokenError("Invalid token type")
        return payload

    def _create_token(self, user_id: int, token_type: str, expires_minutes: int) -> str:
        """Собирает JWT с указанным типом и временем жизни."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "type": token_type,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
            "iss": settings.app_name,
        }
        return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


tokens = TokenHelper()
