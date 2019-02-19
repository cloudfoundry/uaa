package org.cloudfoundry.identity.uaa.oauth.openid;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.List;
import java.util.Objects;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;


public class IdTokenGranter {
    private static final Logger logger = LoggerFactory.getLogger(IdTokenGranter.class);

    private final String REQUIRED_OPENID_SCOPE = "openid";
    private final List<String> GRANT_TYPES_THAT_MAY_GET_ID_TOKENS = Lists.newArrayList(
            GRANT_TYPE_AUTHORIZATION_CODE,
            GRANT_TYPE_PASSWORD,
            GRANT_TYPE_IMPLICIT,
            GRANT_TYPE_REFRESH_TOKEN
    );
    private final ApprovalService approvalService;

    public IdTokenGranter(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    public boolean shouldSendIdToken(String userId,
                                     BaseClientDetails clientDetails,
                                     Set<String> requestedScopes,
                                     String requestedGrantType
    ) {
        if (!GRANT_TYPES_THAT_MAY_GET_ID_TOKENS.contains(requestedGrantType)) {
            return false;
        }

        try {
            approvalService.ensureRequiredApprovals(
                    userId, Sets.newHashSet(REQUIRED_OPENID_SCOPE), requestedGrantType, clientDetails
            );
        } catch (InvalidTokenException e) {
            return false;
        }

        // An id token may not be issued unless the client configuration includes
        // the scope openid
        Set<String> clientScopes = clientDetails.getScope();
        if (null == clientScopes || clientScopes.isEmpty()) {
            return false;
        }
        if (clientScopes.stream()
                .filter(Objects::nonNull)
                .noneMatch(REQUIRED_OPENID_SCOPE::equals)) {
            return false;
        }

        // If the requester specified the scope parameter in their /oauth/token request,
        // this list must contain openid.
        if (requestedScopes != null &&
            !requestedScopes.isEmpty() &&
            !requestedScopes.contains(REQUIRED_OPENID_SCOPE)) {
            logger.info("an ID token was requested but 'openid' is missing from the requested scopes");
            return false;
        }

        return true;
    }
}
