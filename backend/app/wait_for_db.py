"""Waits until the database accepts connections, before migrations run.

Without this, the app container crashes and restarts until PostgreSQL is
ready, which delays start-up and hides real failures among expected ones.
"""

import sys
import time

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from app.config import DATABASE_URL

TIMEOUT_SECONDS = 180


def main() -> int:
    engine = create_engine(DATABASE_URL)
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while True:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            print("Database is ready.")
            return 0
        except OperationalError as exc:
            if time.monotonic() > deadline:
                print(f"Database not ready after {TIMEOUT_SECONDS}s: {exc}", file=sys.stderr)
                return 1
            time.sleep(2)


if __name__ == "__main__":
    sys.exit(main())
