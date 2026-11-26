"""Pruefung der Geheimnisse beim Start, ohne Datenbank."""
import jwt
import pytest

from app import config, security

FORGE_PAYLOAD = {"sub": "1", "role": "admin", "ver": 0, "exp": 9999999999}


@pytest.fixture
def env(monkeypatch):
    def set_values(jwt_secret="", admin_password=""):
        monkeypatch.setattr(config, "JWT_SECRET", jwt_secret)
        monkeypatch.setattr(config, "ADMIN_PASSWORD", admin_password)
    return set_values


@pytest.mark.parametrize("value", ["", *sorted(config.PLACEHOLDER_JWT_SECRETS)])
def test_missing_or_placeholder_jwt_secret_replaced(env, value):
    env(jwt_secret=value)
    warnings = config.resolve_secrets()
    assert config.JWT_SECRET != value and len(config.JWT_SECRET) >= config.MIN_JWT_SECRET_BYTES
    assert any("JWT_SECRET" in w for w in warnings)


def test_token_forged_with_placeholder_rejected(env):
    env(jwt_secret="change-me-jwt-at-least-32-characters-long")
    config.resolve_secrets()
    forged = jwt.encode(FORGE_PAYLOAD, "change-me-jwt-at-least-32-characters-long", algorithm="HS256")
    with pytest.raises(jwt.InvalidSignatureError):
        security.decode_token(forged)


def test_short_jwt_secret_aborts_start(env):
    env(jwt_secret="zu-kurz")
    with pytest.raises(config.ConfigError):
        config.resolve_secrets()


def test_own_jwt_secret_kept(env):
    own = "ein-eigener-schluessel-der-lang-genug-ist-123"
    env(jwt_secret=own)
    assert config.resolve_secrets() == []
    assert config.JWT_SECRET == own


def test_placeholder_admin_password_ignored(env):
    env(jwt_secret="ein-eigener-schluessel-der-lang-genug-ist-123", admin_password="change-me-admin")
    warnings = config.resolve_secrets()
    assert config.ADMIN_PASSWORD == ""
    assert any("ADMIN_PASSWORD" in w for w in warnings)


def test_short_admin_password_aborts_start(env):
    env(jwt_secret="ein-eigener-schluessel-der-lang-genug-ist-123", admin_password="admin")
    with pytest.raises(config.ConfigError):
        config.resolve_secrets()
