package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

public class ClientAccessTokenValidity implements ClientTokenValidity {
    private final Log logger = LogFactory.getLog(getClass());
    private ClientServicesExtension clientServicesExtension;

    public ClientAccessTokenValidity(ClientServicesExtension clientServicesExtension) {
        this.clientServicesExtension = clientServicesExtension;
    }

    @Override
    public Integer getValiditySeconds(String clientId) {
        ClientDetails clientDetails;
        try {
            clientDetails = clientServicesExtension.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
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
