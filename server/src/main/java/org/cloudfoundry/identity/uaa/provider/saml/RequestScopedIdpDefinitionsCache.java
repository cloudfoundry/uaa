package org.cloudfoundry.identity.uaa.provider.saml;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

@RequestScope
@Component("requestScopedIdpDefinitionsCache")
public class RequestScopedIdpDefinitionsCache {
    private final ConcurrentHashMap<String, List<IdentityProvider>> zoneIdps = new ConcurrentHashMap<>();

    public void setIdps(String zoneId, List<IdentityProvider> idps) {
        zoneIdps.put(zoneId, idps);
    }

    public List<IdentityProvider> getIdps(String zoneId) {
        return zoneIdps.get(zoneId);
    }
}
