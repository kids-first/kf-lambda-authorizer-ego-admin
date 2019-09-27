import os

import jwt
import requests

PUBLIC_KEY_URL_ENV = 'EGO_PUBLIC_KEY_URL'


def download_public_key():
    return requests.get(
        os.environ[PUBLIC_KEY_URL_ENV]).text


def copy_if_define(f, to, key):
    if key in f.keys():
        to[key] = f[key]


class Authorizer(object):
    # Lazy initialization of static variable, fetching public key cost, so it's only done for the first initialization
    __public_key = None

    @staticmethod
    def public_key():
        """Get public key to decrypt JWT token"""
        if not Authorizer.__public_key:
            Authorizer.__public_key = download_public_key()
        return Authorizer.__public_key

    def __init__(self, token, arn) -> None:
        """
        Build the policy on an ARN, depending on the roles defined in an encoded JWT token from EGO.
        If the roles contains ADMIN, then an ALLOW policy is built, otherwise a DENY policy is build.
        If the token is not valid, an error is raised.
        """
        self.token = token
        self.arn = arn

    def policy(self):
        decoded_token = jwt.decode(self.token, Authorizer.public_key(), algorithms='RS256',
                                   options={'verify_aud': False})
        is_allowed = Authorizer.authorize_user(decoded_token)
        return Authorizer.build_policy(decoded_token, self.arn, is_allowed)

    @staticmethod
    def authorize_user(token):
        return 'ADMIN' in token.get('context', {}).get('user', {}).get('roles', {})

    @staticmethod
    def build_policy(token, resource, is_allowed):
        policy = {
            'principalId': token['sub'],
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': 'execute-api:Invoke',
                        'Effect': 'Allow' if is_allowed else 'Deny',
                        'Resource': resource,
                    },
                ],
            }
        }
        user = token['context']['user']

        context = {}
        copy_if_define(user, context, 'name')
        copy_if_define(user, context, 'email')
        copy_if_define(user, context, 'status')
        copy_if_define(user, context, 'firstName')
        copy_if_define(user, context, 'lastName')

        if context.keys():
            policy['context'] = context

        return policy
