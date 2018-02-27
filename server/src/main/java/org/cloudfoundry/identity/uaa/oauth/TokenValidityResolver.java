package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.joda.time.DateTime;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import java.util.Date;

import static java.util.Optional.ofNullable;

public class TokenValidityResolver {
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
            clientDetailsService.loadClientByClientId(clientId).getAccessTokenValiditySeconds()
        ).orElse(
            IdentityZoneHolder.get().getConfig().getTokenPolicy().getAccessTokenValidity()
        );

        if (tokenValiditySeconds == DEFAULT_TO_GLOBAL_POLICY) {
            tokenValiditySeconds = globalAccessTokenValiditySeconds;
        }

        return DateTime.now().plusSeconds(tokenValiditySeconds).toDate();
    }
}
