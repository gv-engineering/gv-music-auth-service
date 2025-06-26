import datetime
import hashlib
import secrets
from datetime import timedelta

import bcrypt
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from common.constants import ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM, SECRET_KEY_REGISTER, ALGORITHM_HASH
from crud.auth_services import user_cruds, role_cruds
from models.user_models import UserModel
from scheme.auth_scheme import UserRegister, User, UserCreate


class AuthService:
    @classmethod
    async def create_user_with_admin(cls, data: UserRegister, session: AsyncSession):
        cls.get_valid_bd_user(data)
        role = 'admin'
        try:
            jwt.decode(data.token_author, SECRET_KEY_REGISTER, algorithms=[ALGORITHM_HASH])
        except:
            role = 'user'
        if await user_cruds.get_by_value(username=data.username, db=session):
            return None
        valid_data = cls.get_valid_bd_user(data)
        admin_role = await role_cruds.get_by_value(db=session, role_name=role)
        admin_role_id = admin_role.id
        valid_data.role_id = admin_role_id
        user = await user_cruds.create(db=session, object_in=valid_data)
        return user


    @classmethod
    def hash_password(cls,password: str) -> str:
        solt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), solt)
        return hashed.decode('utf-8')


    @classmethod
    def verify_password(cls,password_hashed: str,password: str) -> bool:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            password_hashed.encode('utf-8')
        )

    @classmethod
    def get_valid_bd_user(cls, data: UserRegister) -> UserCreate:
        password_hashed = cls.hash_password(data.password)
        user = UserCreate(password_hashed=password_hashed, username=data.username)
        return user


    @classmethod
    async def auth_user(cls, data: OAuth2PasswordRequestForm, session: AsyncSession) -> UserModel | None:
        user = await user_cruds.get_by_value(db=session, username=data.username, options=[selectinload(UserModel.role)])
        if user:
            if cls.verify_password(user.password_hashed, data.password):
                return user
        return None


def create_token(sub: int, role: int, expires_delta: timedelta | None = None) -> str:
    now_time = datetime.datetime.now()
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = expires_delta + now_time

    payload = {
        "sub": str(sub),
        "role": str(role),
        "iat": now_time,
        "expire": int(expire.timestamp())
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(expires_at: datetime.datetime = None) -> tuple[str, str, datetime.datetime]:
    token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if expires_at is None:
        expires_at = datetime.datetime.now() + timedelta(days=15)
    return token, token_hash, expires_at


def create_register_token(expires_at: datetime.datetime = None) -> str:
    expire = 0
    if expires_at is None:
        expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) + datetime.datetime.now()
    token = jwt.encode({'expire': int(expire.timestamp())}, SECRET_KEY_REGISTER, algorithm=ALGORITHM_HASH)
    return token