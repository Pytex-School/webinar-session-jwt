from datetime import datetime, timedelta, timezone

from auth_app.core.config import settings
from auth_app.core.db_manager import DBManager
from auth_app.core.exceptions import (
    InvalidCredentialsError,
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from auth_app.core.security import security
from auth_app.domain.schemas import TokenPair
from auth_app.core.tokens import tokens


class UserService:
    def __init__(self, db: DBManager):
        self.db = db

    async def register(self, name: str, password: str):
        existing = await self.db.users.get_user_by_name(name)
        if existing:
            raise UserAlreadyExistsError
        user = await self.db.users.create_user(name=name, password_hash=security.hash_password(password))
        await self.db.session.commit()
        return user


class AuthServiceSession:
    def __init__(self, db: DBManager):
        self.db = db

    async def login(self, name: str, password: str):
        user = await self.db.users.get_user_by_name(name)
        if not user or not security.verify_password(password, user.password_hash):
            raise InvalidCredentialsError
        raw_token, token_hash = tokens.generate_session_token()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.session_extend_minutes)
        await self.db.auth.create_session(user_id=user.id, token_hash=token_hash, expires_at=expires_at)
        await self.db.session.commit()
        return user, raw_token

    async def logout(self, raw_token: str | None) -> None:
        if not raw_token:
            return
        token_hash = tokens.hash_session_token(raw_token)
        stored = await self.db.auth.get_session_by_hash(token_hash)
        if stored:
            await self.db.auth.delete_session(stored)
            await self.db.session.commit()


class AuthServiceJWT:
    def __init__(self, db: DBManager):
        self.db = db

    async def login(self, name: str, password: str):
        user = await self._get_user_or_raise(name, password)
        pair = await self._issue_tokens(user.id)
        return pair.access_token, pair.refresh_token

    async def refresh(self, raw_refresh_token: str):
        stored = await self._get_valid_refresh(raw_refresh_token)
        user = await self._get_user_for_token(stored.user_id)
        await self.db.auth.delete_refresh_token(stored)  # можно удалять пачками через cron
        pair = await self._issue_tokens(user.id)
        return pair

    async def _get_valid_refresh(self, raw_refresh_token: str):
        token_hash = tokens.hash_session_token(raw_refresh_token)
        stored = await self.db.auth.get_refresh_token(token_hash)
        if not stored or stored.revoked:
            raise RefreshTokenNotFoundError
        now = datetime.now(timezone.utc)
        if stored.expires_at <= now:
            await self.db.auth.delete_refresh_token(stored)  # можно удалять пачками через cron
            raise RefreshTokenExpiredError
        return stored

    async def _get_user_for_token(self, user_id: int):
        user = await self.db.users.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError
        return user

    async def _get_user_or_raise(self, name: str, password: str):
        user = await self.db.users.get_user_by_name(name)
        if not user or not security.verify_password(password, user.password_hash):
            raise InvalidCredentialsError
        return user

    def _refresh_expiry(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(minutes=settings.refresh_token_expires_minutes)

    async def _issue_tokens(self, user_id: int) -> TokenPair:
        access_token = tokens.create_access_token(user_id)
        refresh_token = tokens.create_refresh_token()
        refresh_hash = tokens.hash_session_token(refresh_token)
        expires_at = self._refresh_expiry()
        await self.db.auth.create_refresh_token(user_id=user_id, token_hash=refresh_hash, expires_at=expires_at)
        await self.db.session.commit()
        return TokenPair(access_token=access_token, refresh_token=refresh_token)
