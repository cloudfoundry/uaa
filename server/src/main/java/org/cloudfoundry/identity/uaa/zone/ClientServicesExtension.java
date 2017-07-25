/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;

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
