-- Создание таблицы пользователей
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(100) NOT NULL,
    age INT
);

-- Индекс по полю username для быстрого поиска
CREATE INDEX idx_users_username ON users(username);

-- Создание таблицы проектов
CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    height FLOAT NOT NULL,
    width FLOAT NOT NULL,
    long FLOAT NOT NULL,
    weight FLOAT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_id ON packages(user_id);

-- Добавление тестовых данных
INSERT INTO users (username, email, hashed_password, age)
VALUES ('admin', 'admin@example.com', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 8);
