import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests"}
    )


# Задания 6.4, 6.5, 7.1 =====================================================
class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "guest"


class UserLogin(BaseModel):
    username: str
    password: str


class UserInDB(BaseModel):
    username: str
    hashed_password: str
    role: str


fake_users_db: dict[str, UserInDB] = {}

roles_permissions = {
    "admin": ["create", "read", "update", "delete"],
    "user": ["read", "update"],
    "guest": ["read"]
}


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def find_user_by_username(username: str):
    for stored_username, user in fake_users_db.items():
        if secrets.compare_digest(stored_username, username):
            return user
    return None


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")

        if username is None or role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        return {"username": username, "role": role}

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials
    return verify_access_token(token)


def require_roles(allowed_roles: list[str]):
    def role_checker(current_user=Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        return current_user
    return role_checker


@app.post("/register", status_code=201)
@limiter.limit("1/minute")
def register(request: Request, user: UserCreate):
    existing_user = find_user_by_username(user.username)

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )

    if user.role not in roles_permissions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role"
        )

    fake_users_db[user.username] = UserInDB(
        username=user.username,
        hashed_password=get_password_hash(user.password),
        role=user.role
    )

    return {"message": "New user created"}


@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, user: UserLogin):
    existing_user = find_user_by_username(user.username)

    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if not verify_password(user.password, existing_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed"
        )

    access_token = create_access_token(
        data={"sub": user.username, "role": existing_user.role}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@app.get("/protected_resource")
def protected_resource(
    current_user=Depends(require_roles(["admin", "user"]))
):
    return {
        "message": "Access granted",
    }


@app.post("/admin/create")
def admin_create(
    current_user=Depends(require_roles(["admin"]))
):
    return {
        "message": "Resource created by admin",
        "permissions": roles_permissions[current_user["role"]]
    }


@app.get("/user/read")
def user_read(
    current_user=Depends(require_roles(["admin", "user", "guest"]))
):
    return {
        "message": "Resource available for reading",
        "permissions": roles_permissions[current_user["role"]]
    }


@app.put("/user/update")
def user_update(
    current_user=Depends(require_roles(["admin", "user"]))
):
    return {
        "message": "Resource updated",
        "permissions": roles_permissions[current_user["role"]]
    }


@app.delete("/admin/delete")
def admin_delete(
    current_user=Depends(require_roles(["admin"]))
):
    return {
        "message": "Resource deleted by admin",
        "permissions": roles_permissions[current_user["role"]]
    }