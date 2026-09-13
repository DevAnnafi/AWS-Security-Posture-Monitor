from api.db.models import Base
from api.db.session import engine


def create_tables():
    Base.metadata.create_all(engine)


if __name__ == "__main__":
    create_tables()
    print("tables created")