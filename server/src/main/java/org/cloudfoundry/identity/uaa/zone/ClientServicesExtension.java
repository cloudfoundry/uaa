package org.cloudfoundry.identity.uaa.zone;

import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;

public interface ClientServicesExtension extends ClientRegistrationService, ClientDetailsService {

    void addClientSecret(String clientId, String newSecret) throws NoSuchClientException;

    void deleteClientSecret(String clientId) throws NoSuchClientException;
}
