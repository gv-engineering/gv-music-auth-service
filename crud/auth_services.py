import datetime

from asyncpg.pgproto.pgproto import timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from crud.crud_base import CRUDBase
from models.user_models import UserModel, RefreshTokensModel, RoleModel
from scheme.refresh_token_scheme import TokenUpdate, TokenCreate
from scheme.auth_scheme import Role, RoleCreate, UserCreate


class UserCrud(CRUDBase[UserModel, UserCreate, UserCreate]):

    @classmethod
    async def add_user(cls, data: UserCreate, session: AsyncSession) -> UserModel:
        user = UserModel(
            username=data.username,
            author_token=data.token_author,
            password_hashed=data.password,
            role_id=data.role_id)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    @classmethod
    async def get_user_by_name(cls,username: str, session: AsyncSession) -> (UserModel | None):
        stmt = select(UserModel).filter_by(username=username)
        result = await session.execute(stmt)

        return result.scalars().first()

    @staticmethod
    async def get_refresh_token(token_hash: str,session: AsyncSession,revoked: bool = False) -> RefreshTokensModel | None:
        stmt = select(RefreshTokensModel).filter_by(token_hash=token_hash, revoked=revoked)
        result = await session.execute(stmt)
        result = result.scalar_one_or_none()
        return result

    @staticmethod
    async def save_refresh_token(token_hash: str, user_id: int, session: AsyncSession, expires_at: datetime.datetime = None):
        if expires_at is None:
            expires_at = timedelta(days=15) + datetime.datetime.now()
        token = RefreshTokensModel(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at
        )
        session.add(token)
        await session.commit()

user_cruds = UserCrud(UserModel)
refresh_tokens_cruds = CRUDBase[RefreshTokensModel, TokenUpdate, TokenCreate](RefreshTokensModel)
role_cruds = CRUDBase[RoleModel, Role, RoleCreate](RoleModel)