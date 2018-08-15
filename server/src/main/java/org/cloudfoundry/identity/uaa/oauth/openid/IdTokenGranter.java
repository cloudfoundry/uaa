package org.cloudfoundry.identity.uaa.oauth.openid;

import com.google.common.collect.Lists;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.*;


public class IdTokenGranter {
    private final String REQUIRED_OPENID_SCOPE = "openid";
    private final String REQUIRED_RESPONSE_TYPE = "id_token";
    private final List<String> GRANT_TYPES_THAT_MAY_GET_ID_TOKENS = Lists.newArrayList(
            GRANT_TYPE_AUTHORIZATION_CODE,
            GRANT_TYPE_PASSWORD,
            GRANT_TYPE_IMPLICIT
    );

    public boolean shouldSendIdToken(Collection<GrantedAuthority> clientScopes,
                                            Set<String> requestedScopes,
                                            String requestedGrantType,
                                            Set<String> requestedResponseTypes) {

        // TODO: this needs to consider user approvals / autoapproved scopes

        if (null == requestedResponseTypes) {
            return false;
        }

        if (!GRANT_TYPES_THAT_MAY_GET_ID_TOKENS.contains(requestedGrantType)) {
            return false;
        }

        // An id token may not be issued unless the client configuration includes
        // the scope openid
        if (null == clientScopes) {
            return false;
        }
        if (clientScopes.stream()
                .filter(Objects::nonNull)
                .noneMatch(scope -> REQUIRED_OPENID_SCOPE.equals(scope.getAuthority()))) {
            return false;
        }

        if (GRANT_TYPE_AUTHORIZATION_CODE.equals(requestedGrantType) &&
                requestedResponseTypes.contains("code") &&
                requestedScopes != null &&
                requestedScopes.contains(REQUIRED_OPENID_SCOPE)) {
            return true;
        }

        // If the requester specified the scope parameter in their /oauth/token request,
        // this list must contain openid.
        if (null != requestedScopes &&
            !requestedScopes.isEmpty() &&
            !requestedScopes.contains(REQUIRED_OPENID_SCOPE)) {
            return false;
        }

        // Other than the authorization_code code flow special case, an id token may
        // not be issued unless id_token appears in the response types specified with
        // the response_type param.
        if (requestedResponseTypes
                .stream()
                .noneMatch(responseType -> REQUIRED_RESPONSE_TYPE.equals(responseType))) {
            return false;
        }

        return true;
    }
}
