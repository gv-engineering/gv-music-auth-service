from fastapi.exceptions import HTTPException
CredentialsException = HTTPException(
    status_code=401,
    detail='Failed to verify account details',
    headers={"WWW-Authenticate": "Bearer"}
)
InvalidTokenException = HTTPException(
    status_code=401,
    detail='Invalid token',
    headers={"WWW-Authenticate": "Bearer"}
)
UserNotFoundException = HTTPException(
    status_code=404,
    detail='User not found'
)
UserAlreadyExistException = HTTPException(
    status_code=409,
    detail='User already exists'
)
TokenRefreshIsNotFoundException = HTTPException(
    status_code=401,
    detail='Token refresh isn\'t found'
)
TokenJWTExpiredException = HTTPException(
    status_code=401,
    detail='Token expired',
    headers={"WWW-Authenticate": "Bearer"}
)
