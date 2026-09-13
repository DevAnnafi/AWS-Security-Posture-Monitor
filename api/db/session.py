import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

load_dotenv()

DATABASE_URL = f"postgresql+psycopg2://zihan_aws_sec:{os.environ['POSTGRES_PASSWORD']}@localhost:5433/security_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)