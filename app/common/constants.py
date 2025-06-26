from dotenv import load_dotenv
import os

with open('../private.pem', 'r') as file:
    SECRET_KEY = file.read()

with open('../public.pem', 'r') as file:
    PUBLIC_KEY = file.read()


load_dotenv()
SECRET_KEY_REGISTER = os.getenv('SECRET_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')

ALGORITHM = 'RS256'
ALGORITHM_HASH = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30