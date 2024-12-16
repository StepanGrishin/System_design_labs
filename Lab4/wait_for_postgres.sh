#!/bin/sh

# Ждем доступности PostgreSQL сервера
while ! pg_isready -h db -p 5432 -U "$POSTGRES_USER"; do
  echo "Waiting for Postgres..."
  sleep 1
done

echo "Postgres is up - proceeding to start the app"
exec uvicorn main:app --host 0.0.0.0 --port 8000
