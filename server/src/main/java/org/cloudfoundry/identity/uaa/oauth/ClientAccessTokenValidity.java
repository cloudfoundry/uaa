package org.cloudfoundry.identity.uaa.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

public class ClientAccessTokenValidity implements ClientTokenValidity {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private MultitenantClientServices multitenantClientServices;

    public ClientAccessTokenValidity(MultitenantClientServices multitenantClientServices) {
        this.multitenantClientServices = multitenantClientServices;
    }

    @Override
    public Integer getValiditySeconds(String clientId) {
        ClientDetails clientDetails;
        try {
            clientDetails = multitenantClientServices.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        } catch(ClientRegistrationException e) {
            logger.info("Could not load details for client " + clientId, e);
            return null;
        }
        return clientDetails.getAccessTokenValiditySeconds();
    }

    @Override
    public Integer getZoneValiditySeconds() {
        return IdentityZoneHolder.get().getConfig().getTokenPolicy().getAccessTokenValidity();
    }

}
