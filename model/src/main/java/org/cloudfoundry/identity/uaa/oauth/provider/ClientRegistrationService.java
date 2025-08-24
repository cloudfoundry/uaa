package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;

import java.util.List;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 framework
 */
public interface ClientRegistrationService {

    void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException;

    void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException;

    void updateClientSecret(String clientId, String secret) throws NoSuchClientException;

    void removeClientDetails(String clientId) throws NoSuchClientException;

    List<ClientDetails> listClientDetails();

}
