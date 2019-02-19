# Cloud Foundry Login Server

Handles authentication on `cloudfoundry.com` and delegates all other
identity management tasks to the UAA.  Also provides OAuth2 endpoints
issuing tokens to client apps for `cloudfoundry.com` (the tokens come
from the UAA and no data are stored locally).
