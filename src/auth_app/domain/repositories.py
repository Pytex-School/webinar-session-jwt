from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_app.domain.models import RefreshToken, User, UserSession


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_user_by_name(self, name: str) -> Optional[User]:
        return await self.session.scalar(select(User).where(User.name == name))

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        return await self.session.get(User, user_id)

    async def create_user(self, name: str, password_hash: str) -> User:
        user = User(name=name, password_hash=password_hash)
        self.session.add(user)
        await self.session.flush()
        return user


class AuthRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_session(self, user_id: int, token_hash: str, expires_at: datetime) -> UserSession:
        record = UserSession(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
        self.session.add(record)
        await self.session.flush()
        return record

    async def get_session_by_hash(self, token_hash: str) -> Optional[UserSession]:
        return await self.session.scalar(select(UserSession).where(UserSession.token_hash == token_hash))

    async def delete_session(self, session_obj: UserSession) -> None:
        await self.session.delete(session_obj)

    async def create_refresh_token(self, user_id: int, token_hash: str, expires_at: datetime) -> RefreshToken:
        token = RefreshToken(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
        self.session.add(token)
        await self.session.flush()
        return token

    async def get_refresh_token(self, token_hash: str) -> Optional[RefreshToken]:
        return await self.session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))

    async def delete_refresh_token(self, token_obj: RefreshToken) -> None:
        await self.session.delete(token_obj)
