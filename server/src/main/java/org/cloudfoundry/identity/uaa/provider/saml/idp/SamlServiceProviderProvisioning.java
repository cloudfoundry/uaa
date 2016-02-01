package org.cloudfoundry.identity.uaa.provider.saml.idp;

import java.util.List;

public interface SamlServiceProviderProvisioning {

    SamlServiceProvider create(SamlServiceProvider identityProvider);

    void delete(String id);

    SamlServiceProvider update(SamlServiceProvider identityProvider);

    SamlServiceProvider retrieve(String id);

    List<SamlServiceProvider> retrieveActive(String zoneId);

    List<SamlServiceProvider> retrieveAll(boolean activeOnly, String zoneId);

    SamlServiceProvider retrieveByEntityId(String entityId, String zoneId);
}
