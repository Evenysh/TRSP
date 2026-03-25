import os
import secrets
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from pydantic import BaseModel

load_dotenv()

MODE = os.getenv("MODE", "DEV")
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "secret")

if MODE not in ("DEV", "PROD"):
    raise ValueError("MODE must be DEV or PROD")

if MODE == "PROD":
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
else:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

security = HTTPBasic(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Задание 6.2 ================================================================
class UserBase(BaseModel):
    username: str


class User(UserBase):
    password: str


class UserInDB(UserBase):
    hashed_password: str


fake_users_db: dict[str, UserInDB] = {}


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


@app.post("/register")
def register(user: User):
    for stored_username in fake_users_db:
        if secrets.compare_digest(stored_username, user.username):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists"
            )

    fake_users_db[user.username] = UserInDB(
        username=user.username,
        hashed_password=get_password_hash(user.password)
    )

    return {"message": f"User {user.username} registered successfully"}


def auth_user(credentials: HTTPBasicCredentials = Depends(security)) -> UserInDB:
    found_user = None

    for stored_username, stored_user in fake_users_db.items():
        if secrets.compare_digest(stored_username, credentials.username):
            found_user = stored_user
            break

    if not found_user or not verify_password(credentials.password, found_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return found_user


@app.get("/login")
def login(current_user: UserInDB = Depends(auth_user)):
    return {"message": "You got my secret, welcome"}


# Задание 6.3 ================================================================
def verify_docs_auth(credentials: HTTPBasicCredentials | None):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )

    correct_username = secrets.compare_digest(credentials.username, DOCS_USER)
    correct_password = secrets.compare_digest(credentials.password, DOCS_PASSWORD)

    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )


@app.get("/docs", include_in_schema=False)
def custom_swagger_ui(
    credentials: HTTPBasicCredentials | None = Depends(security)
):
    if MODE == "PROD":
        raise HTTPException(status_code=404, detail="Not Found")

    verify_docs_auth(credentials)

    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="API docs"
    )


@app.get("/openapi.json", include_in_schema=False)
def custom_openapi(
    credentials: HTTPBasicCredentials | None = Depends(security)
):
    if MODE == "PROD":
        raise HTTPException(status_code=404, detail="Not Found")

    verify_docs_auth(credentials)

    return JSONResponse(app.openapi())


@app.get("/redoc", include_in_schema=False)
def custom_redoc():
    raise HTTPException(status_code=404, detail="Not Found")