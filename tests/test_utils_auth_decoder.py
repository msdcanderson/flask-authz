import os
import pytest
import jwt

from flask_authz.utils import authorization_decoder, UnSupportedAuthType


os.environ["JWT_SECRET_KEY"] = "super-secret-key"

encoded_jwt = jwt.encode({
    "identity": "bob",
}, os.environ["JWT_SECRET_KEY"], algorithm='HS256')

encoded_jwt = encoded_jwt.decode('utf-8')


@pytest.mark.parametrize("auth_str, result", [("Basic Ym9iOnBhc3N3b3Jk", "Bob")])
def test_auth_docode(auth_str, result):
    assert authorization_decoder(auth_str) == "bob"


@pytest.mark.parametrize("auth_str", [(f"Bearer {encoded_jwt}")])
def test_auth_decode_bearer(auth_str):
    assert authorization_decoder(auth_str) == "bob"


@pytest.mark.parametrize(
    "auth_str", [("Unsupported Ym9iOnBhc3N3b3Jk")]
)
def test_auth_docode_exceptions(auth_str):
    with pytest.raises(UnSupportedAuthType):
        authorization_decoder(auth_str)
        