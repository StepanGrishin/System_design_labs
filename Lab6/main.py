from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import DateTime, create_engine, Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel
from typing import Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from confluent_kafka import Producer
import redis
import json

app = FastAPI()

# Конфигурация для JWT и базы данных
SECRET_KEY = "secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:secret@db:5432/postgres"
MONGO_DATABASE_URL = "mongodb://mongodb:27017/"
REDIS_HOST = "redis"
REDIS_PORT = 6379

KAFKA_BROKER = "kafka:9092"

conf = {
    'bootstrap.servers': KAFKA_BROKER  # Адрес Kafka брокера
}

producer = Producer(**conf)

# Подключение к Redis
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# Подключение к MongoDB
client = MongoClient(MONGO_DATABASE_URL)

# Настройки по MongoDB
db_mongo = client['arch']

# Выбор коллекции
collection = db_mongo['orders']

# Инициализация SQLAlchemy
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Конфигурация для хеширования пароля
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# SQLAlchemy модели
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    email = Column(String, index=True)
    hashed_password = Column(String)
    age = Column(Integer, nullable=True)

    # Связь с таблицей PostDB
    Posts = relationship("PostDB", back_populates="user")

class PostDB(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("UserDB", back_populates="Posts")

# Создаем таблицы в базе данных
Base.metadata.create_all(bind=engine)

# Pydantic схемы
class UserCreate(BaseModel):
    id: Optional[int] = None
    username: str
    email: str
    hashed_password: str
    age: Optional[int] = None

    class Config:
        orm_mode = True

class UserResponse(BaseModel):
    id: Optional[int] = None
    username: str
    email: str
    hashed_password: str
    age: Optional[int] = None

    class Config:
        orm_mode = True

class Post(BaseModel):
    id: Optional[int] = None
    user_id: int
    content: str
    created_at: datetime = None

    class Config:
        orm_mode = True  # Включаем поддержку преобразования из ORM

class Message(BaseModel):
    id: Optional[int] = None
    sender_id: int
    receiver_id: int
    body: str
    created_at: datetime = datetime.now(timezone.utc)

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Утилиты
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else timedelta(minutes=15)
    to_encode.update({"exp": expire.total_seconds()})  # Преобразуем в секунды
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Функция для работы с кешем Redis
def get_user_from_cache(username: str):
    user_data = redis_client.get(username)
    if user_data:
        return json.loads(user_data)
    return None

def set_user_in_cache(username: str, user: dict, expire: int = 3600):
    redis_client.set(username, json.dumps(user), ex=expire)

# Authentication routes
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: SessionLocal = Depends(get_db)
):
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    access_token = create_access_token(data={"sub": user.username})
    
    # Возвращаем объект Token
    return Token(access_token=access_token, token_type="bearer")


# User registration
@app.post("/register", response_model=UserCreate)
async def register_user(user: UserCreate, db: SessionLocal = Depends(get_db)):
    hashed_password = get_password_hash(user.hashed_password)
    db_user = UserDB(username=user.username, email=user.email, hashed_password=hashed_password, age=user.age)
    # db.add(db_user)
    # db.commit()
    # db.refresh(db_user)
    
    user_data = UserCreate.from_orm(db_user)
    set_user_in_cache(user.username, user_data.dict())

    kafka_message = user_data.dict()
    print(kafka_message)

    producer.produce(
        "created_user",  # Укажите ваш топик
        key=kafka_message["username"].encode("utf-8"),
        value=json.dumps(kafka_message).encode("utf-8")
    )
    producer.flush()

    return user_data

# CRUD для постов
@app.post("/posts", response_model=Post)
async def create_post(post: Post, db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):
    db_post = PostDB(
        user_id=post.user_id,
        content=post.content,
        created_at=datetime.now(timezone.utc),  # Используем UTC для времени
    )
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    # Преобразуем SQLAlchemy объект в Pydantic
    return Post.from_orm(db_post)

@app.get("/users")
async def read_packages(db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):
    return db.query(UserDB).all()

@app.get("/posts")
async def read_Posts(db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):
    return db.query(PostDB).all()

# CRUD операции
@app.get("/users/{username}", response_model=UserResponse)
async def get_user(username: str, db: SessionLocal = Depends(get_db), token: str = Depends(oauth2_scheme)):
    # Проверяем кеш
    user_data = get_user_from_cache(username)
    if user_data:
        print('Из кэша!!!')
        return user_data

    # Если в кеше нет, то читаем из базы
    db_user = get_user(db, username)
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user = UserResponse.from_orm(db_user)

    # Сохраняем в кеш
    set_user_in_cache(username, user.dict())

    return user

@app.post("/message/", response_model=Message)
def create_user(message: Message):
    insert_result = collection.insert_one(message.__dict__)
    print(f"Order inserted with id: {insert_result.inserted_id}")
    return message

@app.get("/message/", response_model=list[Message])
def get_all_users():
    result = collection.find() 
    # users = db.query(User).all()
    message = [Message(**doc) for doc in result]
    return message
