"""Create the demo accounts. They use a test password from the environment."""

import os

from sqlalchemy import select

from app.auth import hash_password
from app.db import SessionLocal
from app.models import User

ACCOUNTS = (
    ("admin", "admin"),
    ("alice", "member"),
    ("bob", "member"),
    ("auditor", "auditor"),
)


def main() -> None:
    password = os.environ["SEED_PASSWORD"]
    with SessionLocal() as session:
        for username, role in ACCOUNTS:
            exists = session.scalar(select(User).where(User.username == username))
            if exists is None:
                session.add(
                    User(
                        username=username,
                        password_hash=hash_password(password),
                        role=role,
                    )
                )
                session.flush()
        session.commit()


if __name__ == "__main__":
    main()
