import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth import get_current_user
from api.db.session import engine, get_session
from api.db.models import User
from api.main import app


@pytest.fixture
def session():
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(
        bind=connection,
        join_transaction_mode="create_savepoint",
    )

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def client(session):
    test_user = User(
        email="test@example.com",
        password_hash="",
    )

    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: test_user

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()

@pytest.fixture
def anonymous_client(session):
    app.dependency_overrides[get_session] = lambda: session

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()