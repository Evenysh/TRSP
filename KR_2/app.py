from typing import Optional
import time
from uuid import uuid4

from fastapi import FastAPI, Cookie, HTTPException, Response
from pydantic import BaseModel, EmailStr, Field
from itsdangerous import Signer

app = FastAPI()


# Задание 3.1 ================================================================
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    age: Optional[int] = Field(default=None, gt=0)
    is_subscribed: Optional[bool] = None


@app.post("/create_user")
def create_user(user: UserCreate):
    return user


# Задание 3.2 ================================================================
sample_product_1 = {
    "product_id": 123,
    "name": "Smartphone",
    "category": "Electronics",
    "price": 599.99
}

sample_product_2 = {
    "product_id": 456,
    "name": "Phone Case",
    "category": "Accessories",
    "price": 19.99
}

sample_product_3 = {
    "product_id": 789,
    "name": "Iphone",
    "category": "Electronics",
    "price": 1299.99
}

sample_product_4 = {
    "product_id": 101,
    "name": "Headphones",
    "category": "Accessories",
    "price": 99.99
}

sample_product_5 = {
    "product_id": 202,
    "name": "Smartwatch",
    "category": "Electronics",
    "price": 299.99
}

sample_products = [
    sample_product_1,
    sample_product_2,
    sample_product_3,
    sample_product_4,
    sample_product_5
]


@app.get("/products/search")
def search_products(keyword: str, category: str | None = None, limit: int = 10):
    result = []

    for product in sample_products:
        if keyword.lower() in product["name"].lower():
            if category is None or product["category"].lower() == category.lower():
                result.append(product)

    return result[:limit]


@app.get("/product/{product_id}")
def get_product(product_id: int):
    for product in sample_products:
        if product["product_id"] == product_id:
            return product
    return {"message": "Product not found"}


# Задание 5.1-5.2 ============================================================
class ThemeData(BaseModel):
    theme: str


@app.post("/set_theme")
def set_theme(data: ThemeData, response: Response):
    response.set_cookie(
        key="theme",
        value=data.theme,
        httponly=False,
        secure=False,
        max_age=3600
    )
    return {"message": "Theme cookie has been set", "theme": data.theme}


@app.get("/get_theme")
def get_theme(theme: str | None = Cookie(default=None)):
    if theme is None:
        raise HTTPException(status_code=404, detail="Theme cookie not found")

    return {"theme": theme}


# Задание 5.3 ================================================================
SECRET_KEY = "super-secret-key"
signer = Signer(SECRET_KEY)

fake_user = {
    "username": "user123",
    "password": "password123",
    "full_name": "Test User",
    "email": "user123@example.com"
}


class LoginData(BaseModel):
    username: str
    password: str


def build_session_token(user_id: str, timestamp: int) -> str:
    value = f"{user_id}.{timestamp}"
    signature = signer.get_signature(value.encode()).decode()
    return f"{user_id}.{timestamp}.{signature}"


def parse_and_validate_session(session_token: str):
    parts = session_token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="Invalid session")

    user_id, timestamp_str, signature = parts
    value = f"{user_id}.{timestamp_str}"
    expected_signature = signer.get_signature(value.encode()).decode()

    if signature != expected_signature:
        raise HTTPException(status_code=401, detail="Invalid session")

    try:
        last_activity = int(timestamp_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid session")

    now = int(time.time())
    passed = now - last_activity

    if passed > 300:
        raise HTTPException(status_code=401, detail="Session expired")

    return user_id, last_activity, now, passed


@app.post("/login")
def login(data: LoginData, response: Response):
    if data.username != fake_user["username"] or data.password != fake_user["password"]:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user_id = str(uuid4())
    now = int(time.time())
    session_token = build_session_token(user_id, now)

    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=False,
        max_age=300
    )

    return {"message": "Login successful"}


@app.get("/profile")
def profile(response: Response, session_token: str | None = Cookie(default=None)):
    if not session_token:
        raise HTTPException(status_code=401, detail="Invalid session")

    user_id, last_activity, now, passed = parse_and_validate_session(session_token)

    if 180 <= passed < 300:
        new_token = build_session_token(user_id, now)
        response.set_cookie(
            key="session_token",
            value=new_token,
            httponly=True,
            secure=False,
            max_age=300
        )

    return {
        "user_id": user_id,
        "username": fake_user["username"],
        "full_name": fake_user["full_name"],
        "email": fake_user["email"]
    }


# Задание 5.4-5.5 ============================================================
from datetime import datetime
from typing import Annotated
from fastapi import Depends, Header


class CommonHeaders(BaseModel):
    user_agent: str
    accept_language: str


def get_common_headers(
    user_agent: Annotated[str | None, Header(alias="User-Agent")] = None,
    accept_language: Annotated[str | None, Header(alias="Accept-Language")] = None,
) -> CommonHeaders:
    if not user_agent:
        raise HTTPException(status_code=400, detail="User-Agent header is required")

    if not accept_language:
        raise HTTPException(status_code=400, detail="Accept-Language header is required")

    return CommonHeaders(
        user_agent=user_agent,
        accept_language=accept_language
    )


@app.get("/headers")
def read_headers(headers: CommonHeaders = Depends(get_common_headers)):
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language
    }


@app.get("/info")
def read_info(response: Response, headers: CommonHeaders = Depends(get_common_headers)):
    response.headers["X-Server-Time"] = datetime.now().isoformat(timespec="seconds")

    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language
        }
    }