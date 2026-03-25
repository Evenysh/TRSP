import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI()

security = HTTPBasic()

VALID_USERNAME = "admin"
VALID_PASSWORD = "secret"


def check_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    is_correct_username = secrets.compare_digest(
        credentials.username,
        VALID_USERNAME
    )
    is_correct_password = secrets.compare_digest(
        credentials.password,
        VALID_PASSWORD
    )

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


@app.get("/login")
def login(username: str = Depends(check_basic_auth)):
    return {"message": f"Hello, {username}!"}