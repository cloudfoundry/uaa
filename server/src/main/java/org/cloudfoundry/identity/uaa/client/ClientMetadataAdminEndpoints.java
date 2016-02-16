/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
public class ClientMetadataAdminEndpoints {

    private ClientMetadataProvisioning clientMetadataProvisioning;
    private HttpMessageConverter<?>[] messageConverters;

    private static Log logger = LogFactory.getLog(ClientMetadataAdminEndpoints.class);

    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientMetadata retrieveClientMetadata(@PathVariable("client") String clientId) {
        try {
            return clientMetadataProvisioning.retrieve(clientId);
        } catch (EmptyResultDataAccessException erdae) {
            throw new ClientMetadataException("No client metadata found for " + clientId, HttpStatus.NOT_FOUND);
        }
    }

    @RequestMapping(value = "/oauth/clients/meta", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public List<ClientMetadata> retrieveAllClientMetadata() {
        return clientMetadataProvisioning.retrieveAll();
    }

    @RequestMapping(value = "/oauth/clients/{client}/meta", method = RequestMethod.PUT)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientMetadata updateClientMetadata(@RequestBody ClientMetadata clientMetadata,
                                               @PathVariable("client") String clientId) {

        if (StringUtils.hasText(clientMetadata.getClientId())) {
            if (!clientId.equals(clientMetadata.getClientId())) {
                throw new ClientMetadataException("Client ID in body {" + clientMetadata.getClientId() + "} does not match URL path {" + clientId + "}", HttpStatus.BAD_REQUEST);
            }
        } else {
            clientMetadata.setClientId(clientId);
        }
        try {
            return clientMetadataProvisioning.update(clientMetadata);
        } catch (EmptyResultDataAccessException e) {
            throw new ClientMetadataException("No client with ID " + clientMetadata.getClientId(), HttpStatus.NOT_FOUND);
        }
    }

    @ExceptionHandler
    public View handleException(ClientMetadataException cme, HttpServletRequest request) {
        logger.error("Unhandled exception in client metadata admin endpoints.", cme);

        boolean trace = request.getParameter("trace") != null && !request.getParameter("trace").equals("false");
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(cme, trace, cme.getExtraInfo()),
            cme.getStatus()), messageConverters);
    }

    public void setClientMetadataProvisioning(ClientMetadataProvisioning clientMetadataProvisioning) {
        this.clientMetadataProvisioning = clientMetadataProvisioning;
    }

    public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
        this.messageConverters = messageConverters;
    }
}
