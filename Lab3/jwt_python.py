from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from collections import defaultdict

# Конфигурация JWT
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# Модель данных для пользователя
class User(BaseModel):
    id: int
    username: str
    email: str
    hashed_password: str
    name: str
    surname: str
    age: Optional[int] = None

# Модель данных для поста
class Post(BaseModel):
    user_id: int
    content: str
    created_at: datetime

# Модель данных для сообщения
class Message(BaseModel):
    sender_id: int
    receiver_id: int
    body: str
    created_at: datetime

# Временное хранилище
users_db: List[User] = []
posts_db: Dict[int, List[Post]] = defaultdict(list)  # Пользовательские посты
messages_db: Dict[int, List[Message]] = defaultdict(list)  # Сообщения пользователей

# Настройка паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Зависимость для получения текущего пользователя
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = next((u for u in users_db if u.username == username), None)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

# Создание и проверка JWT токенов
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Создание нового пользователя
@app.post("/users", response_model=User)
def create_user(user: User):
    if any(u.username == user.username for u in users_db):
        raise HTTPException(status_code=400, detail="User already exists")
    user.hashed_password = pwd_context.hash(user.hashed_password)
    users_db.append(user)
    return user

# Поиск пользователя по логину
@app.get("/users/{login}", response_model=User)
def get_user_by_login(login: str):
    user = next((u for u in users_db if u.username == login), None)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Поиск пользователя по имени и фамилии
@app.get("/users/search", response_model=List[User])
def search_user(name: str, surname: str):
    results = [user for user in users_db if user.name == name and user.surname == surname]
    if not results:
        raise HTTPException(status_code=404, detail="No users found")
    return results

# Добавление записи на стену
@app.post("/posts", response_model=Post)
def create_post(user_id: int, content: str, current_user: User = Depends(get_current_user)):
    post = Post(user_id=user_id, content=content, created_at=datetime.utcnow())
    posts_db[user_id].append(post)
    return post

# Загрузка стены пользователя
@app.get("/users/{user_id}/wall", response_model=List[Post])
def get_user_wall(user_id: int, current_user: User = Depends(get_current_user)):
    return posts_db[user_id]

# Отправка сообщения пользователю
@app.post("/messages", response_model=Message)
def send_message(sender_id: int, receiver_id: int, body: str, current_user: User = Depends(get_current_user)):
    message = Message(sender_id=sender_id, receiver_id=receiver_id, body=body, created_at=datetime.utcnow())
    messages_db[receiver_id].append(message)
    return message

# Получение списка сообщений для пользователя
@app.get("/users/{user_id}/messages", response_model=List[Message])
def get_user_messages(user_id: int, current_user: User = Depends(get_current_user)):
    return messages_db[user_id]

# Токен аутентификации
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = next((u for u in users_db if u.username == form_data.username), None)
    if user is None or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
