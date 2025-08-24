package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.client.InMemoryClientDetailsService;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;

import java.util.HashMap;
import java.util.Map;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class InMemoryClientDetailsServiceBuilder extends
        ClientDetailsServiceBuilder<InMemoryClientDetailsServiceBuilder> {

    private final Map<String, UaaClientDetails> clientDetails = new HashMap<>();

    @Override
    protected void addClient(String clientId, ClientDetails value) {
        clientDetails.put(clientId, (UaaClientDetails) value);
    }

    @Override
    protected ClientDetailsService performBuild() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(clientDetails);
        return clientDetailsService;
    }

}
