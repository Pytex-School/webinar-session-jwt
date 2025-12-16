from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from auth_app.core.config import settings
from auth_app.api.dependencies import DBManagerDep, get_current_user_from_session
from auth_app.core.exceptions import (
    AppError,
    InvalidCredentialsError,
)
from auth_app.domain.models import User
from auth_app.domain.schemas import LoginRequest, SessionLoginResponse, UserRead
from auth_app.domain.services import AuthServiceSession


router = APIRouter(prefix="/auth", tags=["Session"])


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.session_ttl_minutes * 60,
        domain=settings.session_cookie_domain,
        path="/",
    )

def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        domain=settings.session_cookie_domain,
        samesite="lax",
        secure=settings.session_cookie_secure,
        path="/",
    )


@router.post(
    "/login/session",
    summary="Вход через session",
)
async def login_with_session(
    data: LoginRequest, response: Response, db: DBManagerDep
) -> SessionLoginResponse:
    session_service = AuthServiceSession(db)
    try:
        user, raw_token = await session_service.login(data.name, data.password)
    except InvalidCredentialsError as err:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    except AppError as err:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    _set_session_cookie(response, raw_token)
    return SessionLoginResponse(user=user)


@router.post("/logout/session", summary="Выход из session")
async def logout_session(request: Request, response: Response, db: DBManagerDep) -> dict:
    session_service = AuthServiceSession(db)
    raw_token = request.cookies.get(settings.session_cookie_name)
    try:
        await session_service.logout(raw_token)
    except AppError as err:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    _clear_session_cookie(response)
    return {"detail": "Logged out"}


@router.get("/me/session", summary="Профиль по session")
async def me_session(user: User = Depends(get_current_user_from_session)) -> UserRead:
    return user
