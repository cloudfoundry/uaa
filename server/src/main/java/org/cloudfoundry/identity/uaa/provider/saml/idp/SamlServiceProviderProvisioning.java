
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import java.util.List;

public interface SamlServiceProviderProvisioning {

    SamlServiceProvider create(SamlServiceProvider identityProvider, final String zoneId);

    void delete(String id, String zoneId);

    SamlServiceProvider update(SamlServiceProvider identityProvider, String zoneId);

    SamlServiceProvider retrieve(String id, String zoneId);

    List<SamlServiceProvider> retrieveActive(String zoneId);

    List<SamlServiceProvider> retrieveAll(boolean activeOnly, String zoneId);

    SamlServiceProvider retrieveByEntityId(String entityId, String zoneId);
}
