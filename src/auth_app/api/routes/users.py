from fastapi import APIRouter, HTTPException, status

from auth_app.api.dependencies import DBManagerDep
from auth_app.domain.schemas import UserCreate, UserRead
from auth_app.domain.services import UserService
from auth_app.core.exceptions import AppError, UserAlreadyExistsError


router = APIRouter(prefix="/auth", tags=["Пользователи"])


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="Регистрация пользователя",
)
async def register(data: UserCreate, db: DBManagerDep) -> UserRead:
    service = UserService(db)
    try:
        return await service.register(data.name, data.password)
    except UserAlreadyExistsError as err:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="User already exists") from err
    except AppError as err:
        detail = str(err) or "Bad request"
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=detail) from err
