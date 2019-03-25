package org.cloudfoundry.identity.uaa.zone;

import org.springframework.security.oauth2.provider.*;

import java.util.List;

public abstract class ClientServicesExtension implements ClientRegistrationService, ClientDetailsService {

    public abstract void addClientSecret(String clientId, String newSecret, String zoneId) throws NoSuchClientException;

    public abstract void deleteClientSecret(String clientId, String zoneId) throws NoSuchClientException;

    @Override
    public final void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        addClientDetails(clientDetails, IdentityZoneHolder.get().getId());
    }

    public abstract void addClientDetails(ClientDetails clientDetails, String zoneId) throws ClientAlreadyExistsException;

    @Override
    public final void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        updateClientDetails(clientDetails, IdentityZoneHolder.get().getId());
    }

    public abstract void updateClientDetails(ClientDetails clientDetails, String zoneId) throws NoSuchClientException;

    @Override
    public final void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        updateClientSecret(clientId, secret, IdentityZoneHolder.get().getId());
    }

    public abstract void updateClientSecret(String clientId, String secret, String zoneId) throws NoSuchClientException;

    @Override
    public final void removeClientDetails(String clientId) throws NoSuchClientException {
        removeClientDetails(clientId, IdentityZoneHolder.get().getId());
    }

    public abstract void removeClientDetails(String clientId, String zoneId) throws NoSuchClientException;

    @Override
    public final List<ClientDetails> listClientDetails() {
        return listClientDetails(IdentityZoneHolder.get().getId());
    }

    public abstract List<ClientDetails> listClientDetails(String zoneId);

    @Override
    public final ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        return loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
    }

    public abstract ClientDetails loadClientByClientId(String clientId, String zoneId) throws ClientRegistrationException;
}
