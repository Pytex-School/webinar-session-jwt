import hashlib

import bcrypt


class Security:
    def hash_password(self, password: str) -> str:
        """Хэширует пароль через bcrypt с предварительным SHA-256 прехэшем."""
        digest = self._password_digest(password)
        return bcrypt.hashpw(digest, bcrypt.gensalt()).decode("utf-8")

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Проверяет пароль, сравнивая его хэш с сохранённым bcrypt-хэшем."""
        digest = self._password_digest(password)
        return bcrypt.checkpw(digest, password_hash.encode("utf-8"))

    def _password_digest(self, password: str) -> bytes:
        """SHA-256 прехэш для устранения ограничения длины пароля в bcrypt."""
        return hashlib.sha256(password.encode("utf-8")).digest()


security = Security()
