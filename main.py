from fastapi import FastAPI
from fastapi.responses import FileResponse
from models import User, Feedback

app = FastAPI()

user = User(
  name="Razina Evgeniya",
  id=1
)

feedbacks = []

# 1.2 — html
@app.get("/")
def read_html():
  return FileResponse("index.html")

# 1.4 — получение пользователя
@app.get("/users")
def get_user():
  return user

# 2.1 — отправка отзыва
@app.post("/feedback")
def create_feedback(feedback: Feedback):
  feedbacks.append(feedback)
  return {"message": f"Feedback received. Thank you, {feedback.name}."}