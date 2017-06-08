/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;

public class InMemoryClientServicesExtentions extends ClientServicesExtension {

    public ConcurrentMap<String, Map<String, BaseClientDetails>> services = new ConcurrentHashMap<>();

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
        getInMemoryService(zoneId).put(clientDetails.getClientId(), (BaseClientDetails)clientDetails);
    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails, String zoneId) throws NoSuchClientException {
        addClientDetails(clientDetails, zoneId);
    }

    @Override
    public void updateClientSecret(String clientId, String secret, String zoneId) throws NoSuchClientException {
        ofNullable((BaseClientDetails)loadClientByClientId(clientId, zoneId)).ifPresent(client ->
            client.setClientSecret(secret)
        );
    }

    @Override
    public void removeClientDetails(String clientId, String zoneId) throws NoSuchClientException {
        getInMemoryService(zoneId).remove(clientId);
    }

    @Override
    public List<ClientDetails> listClientDetails(String zoneId) {
        return getInMemoryService(zoneId).entrySet().stream().map(e -> e.getValue()).collect(Collectors.toList());
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId, String zoneId) throws ClientRegistrationException {
        BaseClientDetails result = getInMemoryService(zoneId).get(clientId);
        if (result==null) {
            throw new NoSuchClientException("No client with requested id: " + clientId);
        }
        return result;
    }
}
