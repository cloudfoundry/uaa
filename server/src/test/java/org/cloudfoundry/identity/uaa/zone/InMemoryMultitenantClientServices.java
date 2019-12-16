package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Optional.ofNullable;

public class InMemoryMultitenantClientServices extends MultitenantClientServices {

    private ConcurrentMap<String, Map<String, BaseClientDetails>> services = new ConcurrentHashMap<>();

    public InMemoryMultitenantClientServices(IdentityZoneManager identityZoneManager) {
        super(identityZoneManager);
    }

    public void setClientDetailsStore(String zoneId, Map<String, BaseClientDetails> store) {
        services.put(zoneId, store);
    }

    public Map<String, BaseClientDetails> getInMemoryService(String zoneId) {
        Map<String, BaseClientDetails> clientDetailsStore = new HashMap<>();
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
    public void addClientDetails(ClientDetails clientDetails, String zoneId) throws ClientAlreadyExistsException {
        getInMemoryService(zoneId).put(clientDetails.getClientId(), (BaseClientDetails) clientDetails);
    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails, String zoneId) throws NoSuchClientException {
        addClientDetails(clientDetails, zoneId);
    }

    @Override
    public void updateClientSecret(String clientId, String secret, String zoneId) throws NoSuchClientException {
        ofNullable((BaseClientDetails) loadClientByClientId(clientId, zoneId)).ifPresent(client ->
                client.setClientSecret(secret)
        );
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
        BaseClientDetails result = getInMemoryService(zoneId).get(clientId);
        if (result == null) {
            throw new NoSuchClientException("No client with requested id: " + clientId);
        }
        return result;
    }
}
