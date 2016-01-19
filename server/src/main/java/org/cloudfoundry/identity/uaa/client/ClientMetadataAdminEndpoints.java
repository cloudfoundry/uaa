package org.cloudfoundry.identity.uaa.client;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
@Controller
public class ClientMetadataAdminEndpoints {

    private ClientMetaDetailsProvisioning clientMetaDetailsProvisioning;
    private ClientDetailsService clients;

    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    public ClientMetaDetails createClientUIDetails(@RequestBody ClientMetaDetails clientMetaDetails,
                                                   @PathVariable("client") String clientId)
            throws ClientNotFoundException {

        try {
            clients.loadClientByClientId(clientId);
        } catch (NoSuchClientException nsce) {
            throw new ClientNotFoundException(clientId);
        }

        clientMetaDetails.setClientId(clientId);
        return clientMetaDetailsProvisioning.create(clientMetaDetails);
    }

    // GET
    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    public ClientMetaDetails retrieveClientUIDetails(@PathVariable("client") String clientId) {
        return null;
    }

    // PUT (Update)

    // DELETE

    // GET (retrieveAll)

    public void setClientMetaDetailsProvisioning(ClientMetaDetailsProvisioning clientMetaDetailsProvisioning) {
        this.clientMetaDetailsProvisioning = clientMetaDetailsProvisioning;
    }

    public void setClients(ClientDetailsService clients) {
        this.clients = clients;
    }
}
