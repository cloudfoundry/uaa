# User Account and Authentication: Tokens

## Overview
The UAA is a web application that manages users and Oauth 2 clients and issues tokens that are used for authorization.
The UAA implements [the Oauth 2 authorization framework](http://tools.ietf.org/html/rfc6749) and issues 
[JSON web tokens](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25).
There is often confusion around what the UAA does when initially starting to use it.

This document is intended as a brief introduction to clear up some concepts for those that are new to
Oauth 2 and/or the UAA.

## Getting Started
The easiest way to explain what a token contains and how it is used is to get you to look at one. 
This step requires that you have Java 1.7 or higher installed.


    git clone https://github.com/cloudfoundry/uaa.git
    cd uaa
    ./gradlew run

You now have a UAA server running. There is a Ruby gem called cf-uaac that one can use to communicate with the UAA.
But for sake of clarity, we will use ```curl``` commands.

    curl -v -d"username=marissa&password=koala&client_id=app&grant_type=password" -u "app:appclientsecret" http://localhost:8080/uaa/oauth/token

This yields a return token

    {
      "access_token":"eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJiYzNlNzQ1Ni05MWY1LTQ5NjEtYjg4ZC1kYjcwNTYyNmJhNzciLCJzdWIiOiI3Zjc5MWVhOS05OWI5LTQyM2QtOTg4Yi05MzFmMDIyMmE3OWYiLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLnJlYWQiLCJjbG91ZF9jb250cm9sbGVyLndyaXRlIiwib3BlbmlkIiwicGFzc3dvcmQud3JpdGUiLCJzY2ltLnVzZXJpZHMiXSwiY2xpZW50X2lkIjoiYXBwIiwiY2lkIjoiYXBwIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjdmNzkxZWE5LTk5YjktNDIzZC05ODhiLTkzMWYwMjIyYTc5ZiIsInVzZXJfbmFtZSI6Im1hcmlzc2EiLCJlbWFpbCI6Im1hcmlzc2FAdGVzdC5vcmciLCJpYXQiOjE0MDY1Njg5MzUsImV4cCI6MTQwNjYxMjEzNSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbiIsImF1ZCI6WyJzY2ltIiwib3BlbmlkIiwiY2xvdWRfY29udHJvbGxlciIsInBhc3N3b3JkIl19.ZOhp7HmYF0ufvxXrkut40eHZbHFzAb5EETT2NL7n2Cs",
      "token_type":"bearer",
      "refresh_token":"eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJmYzEwZjVjZC1mODY2LTQzY2MtYTQ4ZS04ZDE3NmY2OGM1MTEiLCJzdWIiOiI3Zjc5MWVhOS05OWI5LTQyM2QtOTg4Yi05MzFmMDIyMmE3OWYiLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLnJlYWQiLCJjbG91ZF9jb250cm9sbGVyLndyaXRlIiwib3BlbmlkIiwicGFzc3dvcmQud3JpdGUiLCJzY2ltLnVzZXJpZHMiXSwiaWF0IjoxNDA2NTY4OTM1LCJleHAiOjE0MDkxNjA5MzUsImNpZCI6ImFwcCIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iLCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX25hbWUiOiJtYXJpc3NhIiwidXNlcl9pZCI6IjdmNzkxZWE5LTk5YjktNDIzZC05ODhiLTkzMWYwMjIyYTc5ZiIsImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyLnJlYWQiLCJjbG91ZF9jb250cm9sbGVyLndyaXRlIiwib3BlbmlkIiwicGFzc3dvcmQud3JpdGUiLCJzY2ltLnVzZXJpZHMiXX0.MWNTyXvGU4YgEFqXToO-D_HplWjfSK0xxqVQc7FYKZg",
      "expires_in":43199,
      "scope":"cloud_controller.read cloud_controller.write openid password.write scim.userids",
      "jti":"bc3e7456-91f5-4961-b88d-db705626ba77"
    }

and the actual value that we are interested in is 

    eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJiYzNlNzQ1Ni05MWY1LTQ5NjEtYjg4ZC1kYjcwNTYyNmJhNzciLCJzdWIiOiI3Zjc5MWVhOS05OWI5LTQyM2QtOTg4Yi05MzFmMDIyMmE3OWYiLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLnJlYWQiLCJjbG91ZF9jb250cm9sbGVyLndyaXRlIiwib3BlbmlkIiwicGFzc3dvcmQud3JpdGUiLCJzY2ltLnVzZXJpZHMiXSwiY2xpZW50X2lkIjoiYXBwIiwiY2lkIjoiYXBwIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjdmNzkxZWE5LTk5YjktNDIzZC05ODhiLTkzMWYwMjIyYTc5ZiIsInVzZXJfbmFtZSI6Im1hcmlzc2EiLCJlbWFpbCI6Im1hcmlzc2FAdGVzdC5vcmciLCJpYXQiOjE0MDY1Njg5MzUsImV4cCI6MTQwNjYxMjEzNSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbiIsImF1ZCI6WyJzY2ltIiwib3BlbmlkIiwiY2xvdWRfY29udHJvbGxlciIsInBhc3N3b3JkIl19.ZOhp7HmYF0ufvxXrkut40eHZbHFzAb5EETT2NL7n2Cs

You can look at the body of the access token using a [decoder](http://jwt.calebb.net/).
More on Tokens can be found [here](https://developers.google.com/accounts/docs/OpenIDConnect#validatinganidtoken) 

    {
        "exp": 1406612135, 
        "user_id": "7f791ea9-99b9-423d-988b-931f0222a79f", 
        "sub": "7f791ea9-99b9-423d-988b-931f0222a79f", 
        "cid": "app", 
        "iss": "http://localhost:8080/uaa/oauth/token", 
        "jti": "bc3e7456-91f5-4961-b88d-db705626ba77", 
        "client_id": "app", 
        "iat": 1406568935, 
        "scope": [
            "cloud_controller.read", 
            "cloud_controller.write", 
            "openid", 
            "password.write", 
            "scim.userids"
        ], 
        "grant_type": "password", 
        "user_name": "marissa", 
        "email": "marissa@test.org", 
        "aud": [
            "scim", 
            "openid", 
            "cloud_controller", 
            "password"
        ]
    }

Some of these fields are described in the [JSON web tokens](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25) 
specification. However, the vendor may add additional fields, or attributes, to the token itself.

There are some notable fields here that we are interested in:

  * user_id — a UUID for the user
  * cid/client_id - a unique name for the client. Unique to the system it runs on.
  * scope — a list of permissions that this client has on behalf of this user
  * [aud](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3) — the audience, who this token is intended for. 

### Users and Clients and other actors
A user is often represented as a live person or a process running.

A client is an application that acts on behalf of a user or acts on its own.

A resource server is often defined as an application with access to a user's data

A brief and informative [tutorial](http://tutorials.jenkov.com/oauth2/index.html) has already been written.

### Grant types
An access token can be requested in four different ways, in the Oauth specification they are referred to as 
[grant types](http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-1.3)

  1. client_credentials — no user involved. requesting a token to represent a client only
  2. password — the client uses the user's credentials and passes them to the UAA to generate a token
     This is the method we used in our example.
  3. implicit — this is similar to the password grant, but a client password(secret) is not needed
  4. authorization_code — in this scenario, the client never sees the user's credentials. It is the most secure
     grant type but relies on 302 redirects from the HTTP protocol.

### Scopes
When it comes to the UAA and integrating with the UAA, you will be dealing with scopes. Scopes are essentially permissions 
and are added as a [named parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-3.3)
in the [access token](http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-3.3).

In the Java world, often referred to as roles. Scopes in a token have two different names in the UAA token

  * scope — when the token represents a client acting on behalf of a user
  * authorities — when the token represents the client (application) itself

This is how the permissions are labeled in the token by the UAA. When a resource server receives a request containing a token, 
the server can make a decision based on the scopes in the token. The resource MUST validate the token first, 
there are several ways of doing this discussed in the Oauth 2 specification. 

The resource server must differentiate between a client only token and read 'authorities', or a client on behalf of the user 
token to read the 'scope' field.

The name of the scope, such as ```password.write``` are arbitrary strings. They don't mean anything to any component except 
the resource server that uses them for authorization. For example, ```password.write``` is a scope that must be present
in the token when a request to the UAA is made for a password change. 

Scopes are arbitrary strings, defined by the client itself. The UAA does use the base name of a scope and adds it to the 
[audience](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3) field. The 'base name' is defined
as anything before the last dot. 

#### Client authorities, UAA groups and scopes
In the UAA each client has a list of ```client authorities```. This is ```List<String>``` of scopes
that represent the permissions the client has by itself. The second field the client has is the ```scopes``` field. 
The ```client scopes``` represents the permissions that the client uses when acting on behalf of a user.
 
Authorities are used when we have the ```client_credentials``` grant type

In the UAA, a user belongs to one or more groups. A group in UAA represents a scope in the Oauth world. Groups can be 
nested allowing easier management of group memberships.

When a client requests a token on behalf of a user, the following process is followed

  1. The client is authenticated
  2. The user is authenticated
  3. The client scopes are retrieved
  4. The user scopes are retrieved
  5. A scope list is created with the shared scopes from steps 3 and 4. 
  6. A token is generated, with the scope parameter from step 5.

#### Wildcard scopes
As scopes are arbitrary strings and those strings often contain dots to create a naming convention.
For example, a resource server maintaining documents could create the following naming scheme

    document.<document id>.read
    document.<document id>.write
    document.<document id>.delete

A client that is accessing the resource server and reading, writing and deleting documents on behalf of a user can be 
assigned the ```scope=document.*.read document.*.delete```. You can now assign scopes to the user in 
the form of

    document.asdsd-adasda-123212.write
    document.asdsd-adasda-123212.read
    document.wqere-adasda-adasda.read
    document.wqere-adasda-adasda.delete

The token representing the user's permission would contain 

    document.asdsd-adasda-123212.read
    document.wqere-adasda-adasda.read
    document.wqere-adasda-adasda.delete
Since the client does not have the ```write```.
The audience field for the token would be ```document```.

A user may not have a wild card in the scope (group name). In that case, the star `*`, does not represent a wildcard;
it's just another character in the arbitrary strings. 
Scope names are [case-sensitive](http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-3.3).
 
Wild card scopes have been available since [UAA version 1.8.0](https://github.com/cloudfoundry/uaa/releases/tag/1.8.0).

### Token enhancers
```UaaTokenEnhancer``` is an interface which can be used to enhance access and refresh tokens with custom attributes. You may plug in a ```UaaTokenEnhancer``` into the bean ```UaaTokenServices```. Values returned by the methods ```getExternalAttributes``` and ```enhance```will be passed to ```setAdditionalInformation``` of the token object.
The interface method ```enhance``` is the successor of ```getExternalAttributes``` and can be used as replacement.

