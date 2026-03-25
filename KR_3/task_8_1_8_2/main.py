from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from database import get_db_connection

app = FastAPI()


# Задание 8.1 ================================================================
class User(BaseModel):
    username: str
    password: str


@app.post("/register")
def register(user: User):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO users (username, password)
        VALUES (?, ?)
        """,
        (user.username, user.password)
    )

    connection.commit()
    connection.close()

    return {"message": "User registered successfully!"}


# Задание 8.2 ================================================================
class TodoCreate(BaseModel):
    title: str
    description: str


class TodoUpdate(BaseModel):
    title: str
    description: str
    completed: bool


@app.post("/todos", status_code=201)
def create_todo(todo: TodoCreate):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO todos (title, description, completed)
        VALUES (?, ?, ?)
        """,
        (todo.title, todo.description, False)
    )

    todo_id = cursor.lastrowid
    connection.commit()
    connection.close()

    return {
        "id": todo_id,
        "title": todo.title,
        "description": todo.description,
        "completed": False
    }


@app.get("/todos/{todo_id}")
def get_todo(todo_id: int):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, title, description, completed
        FROM todos
        WHERE id = ?
        """,
        (todo_id,)
    )

    todo = cursor.fetchone()
    connection.close()

    if todo is None:
        raise HTTPException(status_code=404, detail="Todo not found")

    return {
        "id": todo["id"],
        "title": todo["title"],
        "description": todo["description"],
        "completed": bool(todo["completed"])
    }


@app.put("/todos/{todo_id}")
def update_todo(todo_id: int, todo: TodoUpdate):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM todos
        WHERE id = ?
        """,
        (todo_id,)
    )

    existing_todo = cursor.fetchone()

    if existing_todo is None:
        connection.close()
        raise HTTPException(status_code=404, detail="Todo not found")

    cursor.execute(
        """
        UPDATE todos
        SET title = ?, description = ?, completed = ?
        WHERE id = ?
        """,
        (todo.title, todo.description, todo.completed, todo_id)
    )

    connection.commit()
    connection.close()

    return {
        "id": todo_id,
        "title": todo.title,
        "description": todo.description,
        "completed": todo.completed
    }


@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM todos
        WHERE id = ?
        """,
        (todo_id,)
    )

    existing_todo = cursor.fetchone()

    if existing_todo is None:
        connection.close()
        raise HTTPException(status_code=404, detail="Todo not found")

    cursor.execute(
        """
        DELETE FROM todos
        WHERE id = ?
        """,
        (todo_id,)
    )

    connection.commit()
    connection.close()

    return {"message": "Todo deleted successfully!"}