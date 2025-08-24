package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Optional.ofNullable;

public class InMemoryMultitenantClientServices extends MultitenantClientServices {

    private final ConcurrentMap<String, Map<String, UaaClientDetails>> services = new ConcurrentHashMap<>();

    public InMemoryMultitenantClientServices(IdentityZoneManager identityZoneManager) {
        super(identityZoneManager);
    }

    public void setClientDetailsStore(String zoneId, Map<String, UaaClientDetails> store) {
        services.put(zoneId, store);
    }

    public Map<String, UaaClientDetails> getInMemoryService(String zoneId) {
        Map<String, UaaClientDetails> clientDetailsStore = new HashMap<>();
        services.putIfAbsent(zoneId, clientDetailsStore);
        return services.get(zoneId);
    }

    public void clear() {
        services.clear();
    }

    @Override
    public void addClientSecret(String clientId, String newSecret, String zoneId) throws NoSuchClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void deleteClientSecret(String clientId, String zoneId) throws NoSuchClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addClientJwtConfig(String clientId, String keyConfig, String zoneId, boolean overwrite) throws NoSuchClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addClientJwtCredential(String clientId, ClientJwtCredential keyConfig, String zoneId, boolean overwrite)
            throws NoSuchClientException {
        // ignore
    }

    @Override
    public void deleteClientJwtConfig(String clientId, String keyConfig, String zoneId) throws NoSuchClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void deleteClientJwtCredential(String clientId, ClientJwtCredential keyConfig, String zoneId) throws NoSuchClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void addClientDetails(ClientDetails clientDetails, String zoneId) throws ClientAlreadyExistsException {
        getInMemoryService(zoneId).put(clientDetails.getClientId(), (UaaClientDetails) clientDetails);
    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails, String zoneId) throws NoSuchClientException {
        addClientDetails(clientDetails, zoneId);
    }

    @Override
    public void updateClientSecret(String clientId, String secret, String zoneId) throws NoSuchClientException {
        ofNullable((UaaClientDetails) loadClientByClientId(clientId, zoneId)).ifPresent(client ->
                client.setClientSecret(secret)
        );
    }

    @Override
    public void updateClientJwtConfig(String clientId, String keyConfig, String zoneId) throws NoSuchClientException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeClientDetails(String clientId, String zoneId) throws NoSuchClientException {
        getInMemoryService(zoneId).remove(clientId);
    }

    @Override
    public List<ClientDetails> listClientDetails(String zoneId) {
        return new ArrayList<>(getInMemoryService(zoneId).values());
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId, String zoneId) throws ClientRegistrationException {
        UaaClientDetails result = getInMemoryService(zoneId).get(clientId);
        if (result == null) {
            throw new NoSuchClientException("No client with requested id: " + clientId);
        }
        return result;
    }
}
