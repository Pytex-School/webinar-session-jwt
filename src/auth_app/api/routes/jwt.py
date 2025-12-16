from fastapi import APIRouter, Depends, HTTPException, Response, status

from auth_app.core.config import settings
from auth_app.api.dependencies import DBManagerDep, get_current_user_from_bearer
from auth_app.core.exceptions import (
    AppError,
    InvalidCredentialsError,
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    UserNotFoundError,
)
from auth_app.domain.models import User
from auth_app.domain.schemas import LoginRequest, RefreshRequest, TokenPair, UserRead
from auth_app.domain.services import AuthServiceJWT


router = APIRouter(prefix="/auth", tags=["JWT"])


def _set_token_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        key=settings.access_cookie_name,
        value=access_token,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.access_token_expires_minutes * 60,
        domain=settings.session_cookie_domain,
        path="/",
    )
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=refresh_token,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.refresh_token_expires_minutes * 60,
        domain=settings.session_cookie_domain,
        path="/",
    )


@router.post("/login/jwt", summary="Вход через JWT (access + refresh)")
async def login_with_jwt(
    data: LoginRequest, response: Response, db: DBManagerDep
) -> TokenPair:
    jwt_service = AuthServiceJWT(db)
    try:
        access_token, refresh_token = await jwt_service.login(data.name, data.password)
    except InvalidCredentialsError as err:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except AppError as err:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    _set_token_cookies(response, access_token, refresh_token)
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/token/refresh", summary="Обновление access/refresh токенов")
async def refresh_tokens(
    data: RefreshRequest, response: Response, db: DBManagerDep
) -> TokenPair:
    jwt_service = AuthServiceJWT(db)
    try:
        pair = await jwt_service.refresh(data.refresh_token)
    except RefreshTokenExpiredError as err:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except RefreshTokenNotFoundError as err:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except UserNotFoundError as err:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except AppError as err:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    _set_token_cookies(response, pair.access_token, pair.refresh_token)
    return pair


@router.get("/me/jwt", summary="Профиль по JWT (access)")
async def me_jwt(user: User = Depends(get_current_user_from_bearer)) -> UserRead:
    return user
