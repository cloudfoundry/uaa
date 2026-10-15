package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientRegistrationService;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;

import java.util.List;

interface MultitenantClientRegistrationService extends ClientRegistrationService {

    void addClientDetails(ClientDetails clientDetails, String zoneId) throws ClientAlreadyExistsException;

    void updateClientDetails(ClientDetails clientDetails, String zoneId) throws NoSuchClientException;

    void updateClientSecret(String clientId, String secret, String zoneId) throws NoSuchClientException;

    void updateClientJwtConfig(String clientId, String keyConfig, String zoneId) throws NoSuchClientException;

    void removeClientDetails(String clientId, String zoneId) throws NoSuchClientException;

    List<ClientDetails> listClientDetails(String zoneId);

}

interface MultitenantClientDetailsService extends ClientDetailsService {

    ClientDetails loadClientByClientId(String clientId, String zoneId) throws ClientRegistrationException;

}

interface MultitenantClientSecretService {

    void addClientSecret(String clientId, String newSecret, String zoneId) throws NoSuchClientException;

    void deleteClientSecret(String clientId, String zoneId) throws NoSuchClientException;

    void addClientJwtConfig(String clientId, String keyConfig, String zoneId, boolean overwrite) throws NoSuchClientException;

    void addClientJwtCredential(String clientId, ClientJwtCredential keyConfig, String zoneId, boolean overwrite) throws NoSuchClientException;

    void deleteClientJwtConfig(String clientId, String keyConfig, String zoneId) throws NoSuchClientException;

    void deleteClientJwtCredential(String clientId, ClientJwtCredential keyConfig, String zoneId) throws NoSuchClientException;
}

public abstract class MultitenantClientServices implements
        MultitenantClientRegistrationService,
        MultitenantClientDetailsService,
        MultitenantClientSecretService {

    private final IdentityZoneManager identityZoneManager;

    protected MultitenantClientServices(final IdentityZoneManager identityZoneManager) {
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public final void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        addClientDetails(clientDetails, identityZoneManager.getCurrentIdentityZoneId());
    }

    @Override
    public final void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        updateClientDetails(clientDetails, identityZoneManager.getCurrentIdentityZoneId());
    }

    @Override
    public final void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        updateClientSecret(clientId, secret, identityZoneManager.getCurrentIdentityZoneId());
    }

    @Override
    public final void removeClientDetails(String clientId) throws NoSuchClientException {
        removeClientDetails(clientId, identityZoneManager.getCurrentIdentityZoneId());
    }

    @Override
    public final List<ClientDetails> listClientDetails() {
        return listClientDetails(identityZoneManager.getCurrentIdentityZoneId());
    }

    @Override
    public final ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        return loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
    }
}
