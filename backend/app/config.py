"""Application settings."""

import os

DATABASE_URL = os.environ["DATABASE_URL"]
STORAGE_DIR = os.environ.get("STORAGE_DIR", "/data/documents")

# VULN F05: hard-coded signing key committed to Git. This is a test value only.
SECRET_KEY = "dv-test-9f3K2mQ7xLp4Zt8RwB6nYc1HsV5jGa0E"
