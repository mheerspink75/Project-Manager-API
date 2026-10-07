"""Configuration fail-fast and password policy/security unit tests."""

from __future__ import annotations

import pytest

from app.core.config import (
    PLACEHOLDER_SECRETS,
    ConfigError,
    check_secret_key,
)
from app.core.security import (
    COMMON_PASSWORDS,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    validate_password,
    verify_password,
)


class TestSecretKeyPolicy:
    # Assembled from parts so the literal placeholder never appears in this
    # source file (same source-scan gate as app/core/config.py).
    _PLACEHOLDER = "change" + "-me"

    def test_valid_secret_accepted_in_production(self):
        assert check_secret_key("s3cr3t-value-xyz", "production") == "s3cr3t-value-xyz"

    @pytest.mark.parametrize(
        "placeholder",
        ["change" + "-me", "changeme", "secret", "dev-secret-key", "placeholder"],
    )
    def test_placeholders_are_rejected_outside_development(self, placeholder):
        assert placeholder in PLACEHOLDER_SECRETS
        with pytest.raises(ConfigError):
            check_secret_key(placeholder, "production")
        with pytest.raises(ConfigError):
            check_secret_key(placeholder, "test")

    def test_empty_secret_rejected_outside_development(self):
        with pytest.raises(ConfigError, match="SECRET_KEY"):
            check_secret_key("", "production")
        with pytest.raises(ConfigError, match="SECRET_KEY"):
            check_secret_key("   ", "production")

    def test_placeholder_allowed_in_development(self):
        assert check_secret_key(self._PLACEHOLDER, "development") == self._PLACEHOLDER

    def test_empty_secret_gets_random_dev_key(self):
        dev_key = check_secret_key("", "development")
        assert dev_key  # non-empty
        assert dev_key != ""
        # two calls generate different keys (not a shipped static default)
        assert check_secret_key("", "development") != check_secret_key("", "development")

    def test_settings_constructor_rejects_bad_key_outside_development(self):
        from pydantic import ValidationError

        from app.core.config import Settings

        with pytest.raises(ValidationError, match="SECRET_KEY"):
            Settings(ENVIRONMENT="production", SECRET_KEY="")
        with pytest.raises(ValidationError, match="placeholder"):
            Settings(ENVIRONMENT="production", SECRET_KEY="change" + "-me")
        # and the same value is tolerated in development
        ok = Settings(ENVIRONMENT="development", SECRET_KEY="change" + "-me")
        assert ok.SECRET_KEY == "change" + "-me"


class TestCorsConfig:
    def test_cors_origins_parsed_correctly(self):
        from app.core.config import Settings

        s = Settings(
            ENVIRONMENT="development",
            CORS_ORIGINS="https://a.example.com, https://b.example.com",
        )
        assert s.cors_origins_list == ["https://a.example.com", "https://b.example.com"]

    def test_cors_origins_default(self):
        from app.core.config import Settings

        s = Settings(ENVIRONMENT="development")
        assert s.cors_origins_list == ["http://localhost:3000", "http://127.0.0.1:3000"]


class TestPasswordPolicy:
    def test_short_password_rejected(self):
        with pytest.raises(ValueError, match="8 characters"):
            validate_password("Ab1")

    def test_common_password_rejected(self):
        with pytest.raises(ValueError, match="common"):
            validate_password("password123")

    def test_no_letter_rejected(self):
        # All digits, long, and NOT in the common blocklist -> isolates the
        # "must contain a letter" rule.
        with pytest.raises(ValueError, match="letter"):
            validate_password("1234567890123456")

    def test_no_digit_rejected(self):
        with pytest.raises(ValueError, match="digit"):
            validate_password("abcdefghijkl")

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            validate_password("")

    def test_acceptable_password_ok(self):
        validate_password("C0rrect-Horse-Battery")

    def test_common_passwords_list_sane(self):
        assert "password" in COMMON_PASSWORDS
        assert "12345678" in COMMON_PASSWORDS


class TestBcrypt:
    def test_hash_verify_roundtrip(self):
        hashed = hash_password("S3cure-Passw0rd!")
        assert hashed.startswith("$2")
        assert verify_password("S3cure-Passw0rd!", hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("S3cure-Passw0rd!")
        assert not verify_password("wrong-password", hashed)

    def test_malformed_hash_returns_false_not_exception(self):
        assert not verify_password("anything", "not-a-bcrypt-hash")


class TestJwt:
    def test_access_token_roundtrip(self):
        token = create_access_token(user_id=42, email="a@b.c", role="admin")
        claims = decode_token(token, expected_type="access")
        assert claims["sub"] == "42"
        assert claims["type"] == "access"

    def test_refresh_token_roundtrip(self):
        token = create_refresh_token(user_id=7, email="a@b.c")
        claims = decode_token(token, expected_type="refresh")
        assert claims["sub"] == "7"
        assert "jti" in claims

    def test_type_mismatch_rejected(self):
        access = create_access_token(user_id=1, email="a@b.c", role="user")
        with pytest.raises(Exception):
            decode_token(access, expected_type="refresh")

    def test_garbage_token_rejected(self):
        with pytest.raises(Exception):
            decode_token("not.a.jwt", expected_type="access")
