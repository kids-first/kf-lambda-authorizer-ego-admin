import os
from datetime import datetime, timedelta

import jwt
import pytest
from jwt import DecodeError, ExpiredSignatureError

from authorizer import PUBLIC_KEY_URL_ENV, Authorizer
import importlib.resources as pkg_resources
from . import resources


public_key = pkg_resources.read_text(resources, 'jwt_rs256.pub')
private_key = pkg_resources.read_text(resources, 'jwt_rs256.pem')

PUBLIC_KEY_URL = 'https://my_public_key/oauth/token/public_key'
ARN = '1234'


def encoded_token(user, iat=None, exp=None):
    token = build_token(user, iat, exp)
    return jwt.encode(token, private_key, algorithm='RS256')


def build_token(user, iat=None, exp=None):
    _iat = iat if iat else datetime.utcnow() - timedelta(hours=1)
    _exp = exp if exp else datetime.utcnow() + timedelta(hours=1)
    token = {
        'iat': _iat,
        'exp': _exp,
        'sub': 'user_id',
        'iss': 'ego',
        'aud': [],
        'context': {
            'user': user
        }
    }
    return token


@pytest.fixture(scope='function')
def mock_public_key(requests_mock):
    os.environ[PUBLIC_KEY_URL_ENV] = PUBLIC_KEY_URL
    requests_mock.get(PUBLIC_KEY_URL, text=public_key)


def test_allow_admin_user(mock_public_key):
    user = {
        'name': 'user1@gmail.com',
        'email': 'jecos.user1@gmail.com',
        'status': 'Approved',
        'firstName': 'John',
        'lastName': 'Doe',
        'roles': [
            'ADMIN'
        ]
    }

    result = Authorizer(token=encoded_token(user), arn=ARN).policy()
    assert result == {
        'principalId': 'user_id',
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {'Action': 'execute-api:Invoke', 'Effect': 'Allow', 'Resource': '1234'}
            ]
        },
        'context': {
            'name': 'user1@gmail.com',
            'email': 'jecos.user1@gmail.com',
            'status': 'Approved',
            'firstName': 'John',
            'lastName': 'Doe'
        }
    }


def test_deny_non_admin_user(mock_public_key):
    user = {
        'name': 'user1@gmail.com',
        'email': 'jecos.user1@gmail.com',
        'status': 'Approved',
        'firstName': 'John',
        'lastName': 'Doe',
        'roles': [
            'USER'
        ]
    }

    result = Authorizer(token=encoded_token(user), arn=ARN).policy()
    assert result == {
        'principalId': 'user_id',
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {'Action': 'execute-api:Invoke', 'Effect': 'Deny', 'Resource': '1234'}
            ]
        },
        'context': {
            'name': 'user1@gmail.com',
            'email': 'jecos.user1@gmail.com',
            'status': 'Approved',
            'firstName': 'John',
            'lastName': 'Doe'
        }
    }


def test_raise_error_if_expired_token(mock_public_key):
    user = {
        'name': 'user1@gmail.com',
        'email': 'jecos.user1@gmail.com',
        'status': 'Approved',
        'firstName': 'John',
        'lastName': 'Doe',
        'roles': [
            'ADMIN'
        ]
    }
    expired_token = encoded_token(user, exp=(datetime.utcnow() - timedelta(hours=1)))

    with pytest.raises(ExpiredSignatureError):
        Authorizer(token=expired_token, arn=ARN).policy()


def test_raise_error_if_invalid_token(mock_public_key):
    with pytest.raises(DecodeError):
        Authorizer(token='wrong_token', arn=ARN).policy()


def test_build_policy_with_user():
    user = {
        'firstName': 'John',
        'lastName': 'Doe',
        'email': 'jecos.user1@gmail.com'
    }
    token = build_token(user)
    policy = Authorizer.build_policy(token, ARN, is_allowed=True)
    assert policy == {
        'principalId': 'user_id',
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {'Action': 'execute-api:Invoke', 'Effect': 'Allow', 'Resource': '1234'}
            ]
        },
        'context': {
            'firstName': 'John',
            'lastName': 'Doe',
            'email': 'jecos.user1@gmail.com'
        }
    }


def test_build_policy_without_user():
    token = build_token({})
    policy = Authorizer.build_policy(token, ARN, is_allowed=True)
    assert policy == {
        'principalId': 'user_id',
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {'Action': 'execute-api:Invoke', 'Effect': 'Allow', 'Resource': '1234'}
            ]
        }
    }


def test_build_policy_deny():
    token = build_token({})
    policy = Authorizer.build_policy(token, ARN, is_allowed=False)
    assert policy == {
        'principalId': 'user_id',
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {'Action': 'execute-api:Invoke', 'Effect': 'Deny', 'Resource': '1234'}
            ]
        }
    }
