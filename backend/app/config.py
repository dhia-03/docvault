"""Application settings."""

import os

DATABASE_URL = os.environ["DATABASE_URL"]
STORAGE_DIR = os.environ.get("STORAGE_DIR", "/data/documents")

# VULN F05: hard-coded signing key committed to Git. This is a test value only.
SECRET_KEY = "REMOVED-F05-SIGNING-KEY"
