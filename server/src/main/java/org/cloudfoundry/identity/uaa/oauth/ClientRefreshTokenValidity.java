package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

public class ClientRefreshTokenValidity implements ClientTokenValidity {
    private static final Logger logger = LoggerFactory.getLogger(ClientRefreshTokenValidity.class);

    private final MultitenantClientServices multitenantClientServices;
    private final IdentityZoneManager identityZoneManager;

    public ClientRefreshTokenValidity(
            final MultitenantClientServices multitenantClientServices,
            final IdentityZoneManager identityZoneManager) {
        this.multitenantClientServices = multitenantClientServices;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public Integer getValiditySeconds(String clientId) {
        ClientDetails clientDetails;

        try {
            clientDetails = multitenantClientServices.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
        } catch (ClientRegistrationException e) {
            logger.info("Could not load details for client " + clientId, e);
            return null;
        }
        return clientDetails.getRefreshTokenValiditySeconds();
    }

    @Override
    public Integer getZoneValiditySeconds() {
        return identityZoneManager.getCurrentIdentityZone().getConfig().getTokenPolicy().getRefreshTokenValidity();
    }
}
