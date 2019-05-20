## The App Sample Application

This is a user interface app (primarily aimed at browsers) that uses
OpenId Connect for authentication (i.e. SSO) and OAuth2 for access
grants.  It authenticates with the Auth service, and then accesses
resources in the API service.  Run it with `./gradlew run` from the
`uaa` root directory.

The application can operate in multiple different profiles according
to the location (and presence) of the UAA server and the Login
application.  By default it will look for a UAA on
`localhost:8080/uaa`, but you can change this by setting an
environment variable (or System property) called `UAA_PROFILE`.  In
the application source code (`samples/app/src/main/resources`) you will find
multiple properties files pre-configured with different likely
locations for those servers.  They are all in the form
`application-<UAA_PROFILE>.properties` and the naming convention
adopted is that the `UAA_PROFILE` is `local` for the localhost
deployment, `vcap` for a `vcap.me` deployment, `staging` for a staging
deployment (inside VMware VPN), etc.  The profile names are double
barrelled (e.g. `local-vcap` when the login server is in a different
location than the UAA server).

### Use Cases

1. See all apps

        GET /app/apps

    browser is redirected through a series of authentication and
    access grant steps (which could be slimmed down to implicit steps
    not requiring user at some point), and then the list of apps is shown.

2. See the currently logged in user details, a bag of attributes
grabbed from the open id provider

        GET /app