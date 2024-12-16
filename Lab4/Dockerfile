# Используем Python 3.10
FROM python:3.10

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файл зависимостей
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Устанавливаем PostgreSQL client для использования psql
RUN apt-get update && apt-get install -y postgresql-client

# Копируем скрипт ожидания и делаем его исполняемым
COPY wait-for-postgres.sh .
RUN chmod +x wait-for-postgres.sh

# Копируем основной код приложения
COPY main.py .

# Устанавливаем команду по умолчанию
CMD ["./wait-for-postgres.sh", "./mongo-init.sh","python", "main.py"]
