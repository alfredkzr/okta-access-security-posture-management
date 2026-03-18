"""Edge case tests for src/core/crypto.py."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet, InvalidToken


# We patch settings.encryption_key so tests don't depend on .env
_TEST_KEY = Fernet.generate_key().decode()
_DIFFERENT_KEY = Fernet.generate_key().decode()


def _patched_settings(**overrides):
    """Return a mock settings object with encryption_key set."""
    defaults = {"encryption_key": _TEST_KEY}
    defaults.update(overrides)

    class FakeSettings:
        pass

    obj = FakeSettings()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


@pytest.fixture(autouse=True)
def mock_settings():
    with patch("src.core.crypto.settings", _patched_settings()):
        yield


class TestEncryptToken:
    def test_produces_bytes(self):
        from src.core.crypto import encrypt_token
        result = encrypt_token("hello")
        assert isinstance(result, bytes)

    def test_non_empty_output(self):
        from src.core.crypto import encrypt_token
        result = encrypt_token("hello")
        assert len(result) > 0


class TestDecryptToken:
    def test_recovers_original(self):
        from src.core.crypto import decrypt_token, encrypt_token
        ct = encrypt_token("secret-value")
        assert decrypt_token(ct) == "secret-value"


class TestRoundTrip:
    def test_basic_roundtrip(self):
        from src.core.crypto import decrypt_token, encrypt_token
        original = "my-okta-api-token-12345"
        assert decrypt_token(encrypt_token(original)) == original

    def test_empty_string_roundtrip(self):
        from src.core.crypto import decrypt_token, encrypt_token
        assert decrypt_token(encrypt_token("")) == ""

    def test_unicode_roundtrip(self):
        from src.core.crypto import decrypt_token, encrypt_token
        original = "\u3053\u3093\u306b\u3061\u306f\u4e16\u754c"  # Japanese characters
        assert decrypt_token(encrypt_token(original)) == original

    def test_long_string_roundtrip(self):
        from src.core.crypto import decrypt_token, encrypt_token
        original = "A" * 10000
        assert decrypt_token(encrypt_token(original)) == original

    def test_special_characters_roundtrip(self):
        from src.core.crypto import decrypt_token, encrypt_token
        original = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?"
        assert decrypt_token(encrypt_token(original)) == original


class TestDifferentPlaintexts:
    def test_different_plaintexts_produce_different_ciphertexts(self):
        from src.core.crypto import encrypt_token
        ct1 = encrypt_token("plaintext-one")
        ct2 = encrypt_token("plaintext-two")
        assert ct1 != ct2

    def test_same_plaintext_produces_different_ciphertexts(self):
        """Fernet uses a random IV, so encrypting same text twice should differ."""
        from src.core.crypto import encrypt_token
        ct1 = encrypt_token("same-text")
        ct2 = encrypt_token("same-text")
        assert ct1 != ct2


class TestWrongKey:
    def test_decrypt_with_wrong_key_raises(self):
        from src.core.crypto import encrypt_token
        ct = encrypt_token("secret")

        # Now decrypt with a different key
        with patch("src.core.crypto.settings", _patched_settings(encryption_key=_DIFFERENT_KEY)):
            from src.core.crypto import decrypt_token
            with pytest.raises(InvalidToken):
                decrypt_token(ct)

    def test_decrypt_garbage_raises(self):
        from src.core.crypto import decrypt_token
        with pytest.raises(Exception):
            decrypt_token(b"this-is-not-valid-fernet-data")
