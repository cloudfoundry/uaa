package org.cloudfoundry.identity.uaa.integration.util;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;

public class SimpleSamlPhpIdpCreator implements SamlIdentityProviderCreator {
    private final String originKey;
    private final ServerRunning serverRunning;

    public SimpleSamlPhpIdpCreator(String originKey, ServerRunning serverRunning) {
        this.originKey = originKey;
        this.serverRunning = serverRunning;
    }

    @Override
    public IdentityProvider<SamlIdentityProviderDefinition> createIdp(String baseUrl) {
        try {
            return IntegrationTestUtils.createIdentityProvider(originKey, true, baseUrl, serverRunning);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
