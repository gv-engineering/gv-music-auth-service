from datetime import datetime
from typing import Annotated

from fastapi import Depends
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from common.constants import SECRET_KEY, ALGORITHM, PUBLIC_KEY
from crud.auth_services import user_cruds
from database.init_bd import get_session
from execption.custom_error import CredentialsException, InvalidTokenException, TokenJWTExpiredException
from models.user_models import UserModel
from routs.user_route import scheme_oauth
from scheme.auth_scheme import UserCreate


async def verify_token(token: str = Depends(scheme_oauth)) -> type(scheme_oauth):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload.get('expire'))
        if datetime.fromtimestamp(payload.get('expire')) < datetime.now():
            raise TokenJWTExpiredException
        return token
    except JWTError:
        raise InvalidTokenException


async def get_current_user(token: Annotated[str, Depends(verify_token)],
                           session: AsyncSession = Depends(get_session)) -> dict:
    payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
    user_id = payload.get('sub')
    if user_id is None:
        raise CredentialsException
    user = await user_cruds.get(session, int(user_id), options=([selectinload(UserModel.role)]))
    user = UserCreate(username=user.username, password_hashed='', role_id=str(user.role.role_name))
    return user.model_dump()


async def get_user_info_from_token(token: Annotated[str, Depends(verify_token)]) -> tuple[str, str]:
    payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
    user_id = payload.get('sub')
    role = payload.get('role')
    if user_id is None:
        raise CredentialsException
    return user_id, role


def require_role(require_role: str):
    def role_checker(user: Annotated[dict, Depends(get_current_user)]):
        if user.get('role') == require_role:
            return user
        raise CredentialsException

    return role_checker
