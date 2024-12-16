import kafka
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import UserDB  # Импортируем модель User и базовые настройки

# === PostgreSQL ===
DATABASE_URL = "postgresql://postgres:secret@db:5432/postgres"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# === Kafka ===
KAFKA_BROKER = "kafka:9092"
KAFKA_TOPIC = "created_user"

def main():
    consumer = kafka.KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    )

    print("Consumer is listening for messages...")
    db = SessionLocal()
    for message in consumer:
        event = message.value
        username = event["username"]
        print(f"Processing user creation event for username: {username}")
        user = db.query(UserDB).filter_by(username=username).first()
        if user:
            print(f"User {username} already exists in database.")
        else:
            user = UserDB(username=event['username'], email=event['email'], age=event['age'])
            db.add(user)
            db.commit()
            print(f"User {username} added to database.")
    db.close()

if __name__ == "__main__":
    main()
