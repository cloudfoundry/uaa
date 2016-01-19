package org.cloudfoundry.identity.uaa.client;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
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

    private ClientMetadataProvisioning clientMetadataProvisioning;
    private ClientDetailsService clients;

    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    public ClientMetadata createClientMetadata(@RequestBody ClientMetadata clientMetadata,
                                               @PathVariable("client") String clientId)
            throws ClientNotFoundException {
        try {
            clients.loadClientByClientId(clientId);
        } catch (NoSuchClientException nsce) {
            throw new ClientNotFoundException(clientId );
        }

        clientMetadata.setClientId(clientId);
        return clientMetadataProvisioning.create(clientMetadata);
    }

    // GET
    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    public ClientMetadata retrieveClientMetadata(@PathVariable("client") String clientId) {
        return clientMetadataProvisioning.retrieve(clientId);
    }

    // PUT (Update)
    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.PUT)
    @ResponseStatus(HttpStatus.OK)
    public ClientMetadata updateClientMetadata(@RequestBody ClientMetadata clientMetadata,
                                               @RequestHeader(value = "If-Match", required = false) Integer etag,
                                               @PathVariable("client") String clientId) {
        if (etag == null) {
            throw new ClientMetadataException("Missing If-Match header", HttpStatus.PRECONDITION_FAILED);
        }

        clientMetadata.setVersion(etag);
        return clientMetadataProvisioning.update(clientId, clientMetadata);
    }

    // DELETE

    // GET (retrieveAll)

    public void setClientMetadataProvisioning(ClientMetadataProvisioning clientMetadataProvisioning) {
        this.clientMetadataProvisioning = clientMetadataProvisioning;
    }

    public void setClients(ClientDetailsService clients) {
        this.clients = clients;
    }
}
