import datetime
import hashlib
from typing import Annotated

from fastapi import Form, Depends, APIRouter, Request, Response
from fastapi.responses import JSONResponse
from fastapi.responses import PlainTextResponse
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from crud.auth_services import UserCrud, user_cruds, refresh_tokens_cruds
from database.init_bd import get_session
from execption.custom_error import InvalidTokenException, UserNotFoundException, UserAlreadyExistException, \
    TokenRefreshIsNotFoundException
from middleware.auth_middleware import get_current_user, require_role
from models.user_models import RefreshTokensModel, UserModel
from scheme.auth_scheme import UserRegister, UserInOut
from scheme.refresh_token_scheme import TokenCreate
from services.auth_services import AuthService, create_token, create_refresh_token, create_register_token

router = APIRouter(prefix='/auth')

@router.post('/register', response_model=UserInOut)
async def register(data: Annotated[UserRegister, Form()], session: AsyncSession = Depends(get_session)):
    """
    Endpoint for registering a new user

    Args:
        data: (UserRegister) User data,

    Returns:
        UserInOut: user data with fields: username and role_id
    """
    user = await AuthService.create_user_with_admin(data, session=session)
    if user is None:
        raise UserAlreadyExistException
    return JSONResponse(UserInOut(username=user.username, role_id=str(user.role_id)).model_dump(), status_code=200)


@router.post('/token')
async def token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                session: AsyncSession = Depends(get_session)):
    user_in_db = await AuthService.auth_user(form_data, session)
    if user_in_db:
        token_access = create_token(sub=user_in_db.id, role=user_in_db.role.role_name)
        token_refresh, token_hash, expires_at = create_refresh_token()
        await user_cruds.save_refresh_token(token_hash, user_in_db.id, session=session)
        result = JSONResponse(content={'access_token': token_access, 'token_type': 'bearer'})
        result.set_cookie('refresh_token', value=token_refresh, httponly=True)
        return result
    raise UserNotFoundException


@router.post('/refresh')
async def refresh_token(request: Request, session: Annotated[AsyncSession, Depends(get_session)]):
    token_refresh = request.cookies.get('refresh_token')
    if token_refresh is None:
        raise TokenRefreshIsNotFoundException
    token_hash = hashlib.sha256(token_refresh.encode()).hexdigest()
    token_hash_in_db = await refresh_tokens_cruds.get_by_value(session, token_hash=token_hash, options=[selectinload(RefreshTokensModel.user).selectinload(UserModel.role)])
    if token_hash_in_db is None or token_hash_in_db.expires_at < datetime.datetime.now():
        raise InvalidTokenException
    user_id = token_hash_in_db.user_id
    access_token = create_token(user_id, role=token_hash_in_db.user.role.role_name)
    token_refresh, token_hash, expires_at = create_refresh_token()
    await refresh_tokens_cruds.create(object_in=TokenCreate(token_hash=token_hash, expires_at=expires_at, user_id=user_id), db=session)
    response = JSONResponse({'access_token': access_token, 'token_type': 'bearer'})
    response.set_cookie(key='refresh_token', value=token_refresh)
    return response


@router.get('/get_me')
async def get_me(user_data: Annotated[int, Depends(get_current_user)]):
    return JSONResponse(user_data)


@router.get('/logout')
async def logout(response: Response, request: Request, session: AsyncSession = Depends(get_session)):
    token_ref = request.cookies.get('refresh_token')
    if token_ref:
        token_hash = hashlib.sha256(token_ref.encode()).hexdigest()
        token_from_bd = await refresh_tokens_cruds.get_by_value(db=session, token_hash=token_hash)
        if token_from_bd is None:
            raise InvalidTokenException
        await refresh_tokens_cruds.remove(db=session, id=token_from_bd.id)
        response.status_code = 200
        response.delete_cookie('refresh_token')
        return response
    return None

@router.get('/public-key', response_class=PlainTextResponse)
async def get_public():
    with open('public.pem', 'rb') as f:
        return f.read()

@router.get('/generate-register-token', dependencies=[Depends(require_role('admin'))])
async def get_token_register():
    token_register = create_register_token()
    return JSONResponse({'token': token_register})