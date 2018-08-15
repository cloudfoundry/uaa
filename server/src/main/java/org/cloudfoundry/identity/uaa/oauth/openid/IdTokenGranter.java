package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;


public class IdTokenGranter {
    private static final String OPENID = "openid";

    public static boolean shouldSendIdToken(Collection<GrantedAuthority> clientScopes,
                                            Set<String> requestedScopes,
                                            String requestedGrantType,
                                            Set<String> responseTypes,
                                            boolean isForceIdTokenCreation) {

        // TODO: this needs to consider user approvals / autoapproved scopes

        // An id token may not be issued during client_credentials grants as
        // there is no user context
        if (GRANT_TYPE_CLIENT_CREDENTIALS.equals(requestedGrantType)) {
            return false;
        }

        // This addresses the authorization_code code flow case. The logic currently resides
        // in UaaTokenServices and should migrate here in a future commit.
        // TODO: Migrate this logic from UaaTokenServices and eliminate this force flag.
        if (isForceIdTokenCreation) {
            return true;
        }

        // An id token may not be issued unless the client configuration includes
        // the scope openid
        if (null == clientScopes) {
            return false;
        }
        if (clientScopes.stream()
                .noneMatch(scope -> scope.getAuthority().equals(OPENID))) {
            return false;
        }

        // If the requester specified the scope parameter in their /oauth/token request,
        // this list must contain openid.
        if (null != requestedScopes &&
            !requestedScopes.isEmpty() &&
            !requestedScopes.contains(OPENID)) {
            return false;
        }

        // Other than the isForceIdTokenCreation case above for authorization_code code flow,
        // an id token may not be issued unless id_token appears in the response types specified with
        // the response_type param.
        if (null == responseTypes) {
            return false;
        }
        if (responseTypes
                .stream()
                .noneMatch(responseType -> responseType.equals("id_token"))) {
            return false;
        }

        return true;
    }
}
