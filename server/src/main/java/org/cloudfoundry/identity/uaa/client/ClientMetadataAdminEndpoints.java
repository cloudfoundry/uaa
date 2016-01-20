package org.cloudfoundry.identity.uaa.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

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
    private HttpMessageConverter<?>[] messageConverters;

    private static Log logger = LogFactory.getLog(ClientMetadataAdminEndpoints.class);

    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    public ClientMetadata createClientMetadata(@RequestBody ClientMetadata clientMetadata,
                                               @PathVariable("client") String clientId) {
        try {
            clients.loadClientByClientId(clientId);
            clientMetadata.setClientId(clientId);
            return clientMetadataProvisioning.create(clientMetadata);
        } catch (NoSuchClientException nsce) {
            throw new ClientMetadataException("No client found with id: " + clientId, HttpStatus.NOT_FOUND);
        } catch (DuplicateKeyException e) {
            throw new ClientMetadataException("Client metadata already exists for this clientId: " + clientId, HttpStatus.CONFLICT);
        }

    }

    // GET
    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    public ClientMetadata retrieveClientMetadata(@PathVariable("client") String clientId) {
        try {
            return clientMetadataProvisioning.retrieve(clientId);
        } catch (EmptyResultDataAccessException erdae) {
            throw new ClientMetadataException("No client metadata found for " + clientId, HttpStatus.NOT_FOUND);
        }
    }

    // GET
    @RequestMapping(value = "/oauth/clients/meta", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    public List<ClientMetadata> retrieveAllClientMetadata() {
        return clientMetadataProvisioning.retrieveAll();
    }

    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.DELETE)
    @ResponseStatus(HttpStatus.OK)
    public ClientMetadata deleteClientMetadata(@PathVariable("client") String clientId, @RequestHeader(value = "If-Match", required = false) Integer etag) {
        if (etag == null) {
            throw new ClientMetadataException("Missing If-Match header", HttpStatus.BAD_REQUEST);
        }
        try {
            return clientMetadataProvisioning.delete(clientId, etag);
        } catch (EmptyResultDataAccessException erdae) {
            throw new ClientMetadataException("No client metadata found for " + clientId, HttpStatus.NOT_FOUND);
        } catch (OptimisticLockingFailureException olfe) {
            throw new ClientMetadataException(olfe.getMessage(), HttpStatus.PRECONDITION_FAILED);
        }
    }

    // PUT (Update)
    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.PUT)
    @ResponseStatus(HttpStatus.OK)
    public ClientMetadata updateClientMetadata(@RequestBody ClientMetadata clientMetadata,
                                               @RequestHeader(value = "If-Match", required = false) Integer etag,
                                               @PathVariable("client") String clientId) {
        if (etag == null) {
            throw new ClientMetadataException("Missing If-Match header", HttpStatus.BAD_REQUEST);
        }

        clientMetadata.setVersion(etag);
        try {
            return clientMetadataProvisioning.update(clientId, clientMetadata);
        } catch (OptimisticLockingFailureException olfe) {
            throw new ClientMetadataException(olfe.getMessage(), HttpStatus.PRECONDITION_FAILED);
        }
    }

    @ExceptionHandler
    public View handleException(ClientMetadataException cme, HttpServletRequest request) {
        logger.error("Unhandled exception in client metadata admin endpoints.", cme);

        boolean trace = request.getParameter("trace") != null && !request.getParameter("trace").equals("false");
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(cme, trace, cme.getExtraInfo()),
            cme.getStatus()), messageConverters);
    }

    // DELETE

    // GET (retrieveAll)

    public void setClientMetadataProvisioning(ClientMetadataProvisioning clientMetadataProvisioning) {
        this.clientMetadataProvisioning = clientMetadataProvisioning;
    }

    public void setClients(ClientDetailsService clients) {
        this.clients = clients;
    }

    public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
        this.messageConverters = messageConverters;
    }
}
