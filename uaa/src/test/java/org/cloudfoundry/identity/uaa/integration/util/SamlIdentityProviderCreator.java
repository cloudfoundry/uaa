package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;

public interface SamlIdentityProviderCreator {
    IdentityProvider<SamlIdentityProviderDefinition> createIdp(String baseUrl);
}
