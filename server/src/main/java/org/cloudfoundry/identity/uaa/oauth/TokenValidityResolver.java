package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.joda.time.DateTime;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

import java.util.Date;

import static java.util.Optional.ofNullable;

public class TokenValidityResolver {
    private final Log logger = LogFactory.getLog(getClass());
    public static final int DEFAULT_TO_GLOBAL_POLICY = -1;
    private ClientDetailsService clientDetailsService;
    private int globalAccessTokenValiditySeconds;

    public TokenValidityResolver(ClientDetailsService clientDetailsService,
                                 int globalAccessTokenValiditySeconds) {
        this.clientDetailsService = clientDetailsService;
        this.globalAccessTokenValiditySeconds = globalAccessTokenValiditySeconds;
    }

    public Date resolveAccessTokenValidity(String clientId) {
        Integer tokenValiditySeconds = ofNullable(
            getClientAccessTokenValiditySeconds(clientId)
        ).orElse(
            IdentityZoneHolder.get().getConfig().getTokenPolicy().getAccessTokenValidity()
        );

        if (tokenValiditySeconds == DEFAULT_TO_GLOBAL_POLICY) {
            tokenValiditySeconds = globalAccessTokenValiditySeconds;
        }

        return DateTime.now().plusSeconds(tokenValiditySeconds).toDate();
    }

    private Integer getClientAccessTokenValiditySeconds(String clientId) {
        ClientDetails clientDetails;
        try {
            clientDetails = clientDetailsService.loadClientByClientId(clientId);
        } catch (ClientRegistrationException e) {
            logger.info("Could not load details for client " + clientId, e);
            return null;
        }
        return clientDetails.getAccessTokenValiditySeconds();

    }
}
