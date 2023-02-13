package org.cloudfoundry.identity.uaa.mock.zones;

import java.util.List;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.OrchestratorZoneServiceException;

public class MockIdentityProviderProvisioning implements IdentityProviderProvisioning {

    @Override
    public IdentityProvider create(IdentityProvider identityProvider, String zoneId) {
        throw new OrchestratorZoneServiceException("Mock exception to test transaction rollback");
    }

    @Override
    public IdentityProvider update(IdentityProvider identityProvider, String zoneId) {
        return null;
    }

    @Override
    public IdentityProvider retrieve(String id, String zoneId) {
        return null;
    }

    @Override
    public List<IdentityProvider> retrieveActive(String zoneId) {
        return null;
    }

    @Override
    public List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId) {
        return null;
    }

    @Override
    public IdentityProvider retrieveByOrigin(String origin, String zoneId) {
        return null;
    }
}
