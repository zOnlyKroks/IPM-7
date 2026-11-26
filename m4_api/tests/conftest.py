"""Testkonfiguration. Muss vor dem Import von app.* gesetzt sein, weil config.py die Umgebung beim Import liest."""
import os

os.environ.setdefault("JWT_SECRET", "test-jwt-secret-with-at-least-32-bytes")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "admin-test-password")
os.environ.setdefault("M4_LOGIN_MAX_FAILURES", "3")
if os.getenv("M4_TEST_DATABASE_URL"):
    os.environ["DATABASE_URL"] = os.environ["M4_TEST_DATABASE_URL"]
