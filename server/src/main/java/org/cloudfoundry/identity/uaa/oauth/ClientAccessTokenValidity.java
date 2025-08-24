package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;

import static org.cloudfoundry.identity.uaa.oauth.ClientRefreshTokenValidity.getClientDetails;

public class ClientAccessTokenValidity implements ClientTokenValidity {

    private final MultitenantClientServices multitenantClientServices;
    private final IdentityZoneManager identityZoneManager;

    public ClientAccessTokenValidity(
            final MultitenantClientServices multitenantClientServices,
            final IdentityZoneManager identityZoneManager) {
        this.multitenantClientServices = multitenantClientServices;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public Integer getValiditySeconds(String clientId) {
        ClientDetails clientDetails = getClientDetails(clientId, multitenantClientServices, identityZoneManager);
        return clientDetails != null ? clientDetails.getAccessTokenValiditySeconds() : null;
    }

    @Override
    public Integer getZoneValiditySeconds() {
        return identityZoneManager.getCurrentIdentityZone().getConfig().getTokenPolicy().getAccessTokenValidity();
    }

}
