class AppError(Exception):
    """Базовая ошибка приложения."""


class RepositoryNotInitializedError(AppError):
    """Репозиторий не инициализирован в DBManager."""


class InvalidCredentialsError(AppError):
    """Неверная пара логин/пароль."""


class UserAlreadyExistsError(AppError):
    """Пользователь уже существует."""


class UserNotFoundError(AppError):
    """Пользователь не найден."""


class RefreshTokenNotFoundError(AppError):
    """Рефреш токен не найден или отозван."""


class RefreshTokenExpiredError(AppError):
    """Рефреш токен истёк."""
