package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Moved class InMemoryClientDetailsService implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Serves mainly for tests
 */
public class InMemoryClientDetailsService implements ClientDetailsService {

    private Map<String, UaaClientDetails> clientDetailsStore = new HashMap<>();

    public UaaClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        UaaClientDetails details = clientDetailsStore.get(clientId);
        if (details == null) {
            throw new NoSuchClientException("No client with requested id");
        }
        return details;
    }

    protected void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        String clientId = Optional.ofNullable(clientDetails).orElseThrow(() -> new ClientRegistrationException("No details")).getClientId();
        UaaClientDetails details = clientDetailsStore.get(clientId);
        if (details != null) {
            throw new ClientAlreadyExistsException("Client with this id exists aleady");
        }
        clientDetailsStore.put(clientId, new UaaClientDetails(clientDetails));
    }

    public void setClientDetailsStore(Map<String, ? extends UaaClientDetails> clientDetailsStore) {
        this.clientDetailsStore = new HashMap<>(clientDetailsStore);
    }

}