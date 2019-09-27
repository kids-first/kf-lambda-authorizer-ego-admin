from authorizer import Authorizer


def handler(event, context):
    """Lambda authorizer that build a policy for a JWT token from EGO."""
    token = event['authorizationToken']
    arn = event['methodArn']
    authorizer = Authorizer(token, arn)
    return authorizer.policy()
