package org.cloudfoundry.identity.uaa.oauth;

import org.joda.time.DateTime;

import java.util.Date;

import static java.util.Optional.ofNullable;

public class TokenValidityResolver {
    public static final int DEFAULT_TO_GLOBAL_POLICY = -1;
    private int globalTokenValiditySeconds;
    private ClientTokenValidity clientTokenValidity;

    public TokenValidityResolver(ClientTokenValidity clientTokenValidity,
                                 int globalTokenValiditySeconds) {
        this.clientTokenValidity = clientTokenValidity;
        this.globalTokenValiditySeconds = globalTokenValiditySeconds;
    }

    public Date resolve(String clientId) {
        Integer tokenValiditySeconds = ofNullable(
            clientTokenValidity.getValiditySeconds(clientId)
        ).orElse(
            clientTokenValidity.getZoneValiditySeconds()
        );

        if (tokenValiditySeconds == DEFAULT_TO_GLOBAL_POLICY) {
            tokenValiditySeconds = globalTokenValiditySeconds;
        }

        return DateTime.now().plusSeconds(tokenValiditySeconds).toDate();
    }
}
