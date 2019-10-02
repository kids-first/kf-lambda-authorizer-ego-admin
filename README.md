Kids First Lambda Authorizer EGO Admin
================================

[![CircleCI](https://circleci.com/gh/kids-first/kf-lambda-authorizer-ego-admin.svg?style=svg)](https://circleci.com/gh/kids-first/kf-lambda-authorizer-ego-admin)

A lambda that can be used as an [Authorizer](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html) for AWS API Gateway.

This lambda returns an `Allow` policy if user has role `ADMIN` : 
```
{
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
```   

It returns a `Deny` policy if user has role `ADMIN` :
```
{
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
```

It return an error if the JWT token is not valid (expired, can't be decrypted).


**Note :** Some attributes contained originally in context.user of the JWT token, are also returned in the policy and should be accessible for services called by the API gateway :

- name
- email
- status
- firstname
- lastname


Configuration
-------------

The lambda needs to be configured with the correct variables in the environment :

- `EGO_PUBLIC_KEY_URL` - URL to use to download public key for decrypting the token