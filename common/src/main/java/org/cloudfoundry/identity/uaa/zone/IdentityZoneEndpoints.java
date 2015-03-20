/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

import java.util.UUID;

import javax.validation.Valid;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.oauth.InvalidClientDetailsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/identity-zones")
public class IdentityZoneEndpoints {

    private static final Logger log = LoggerFactory.getLogger(IdentityZoneEndpoints.class);
    private final IdentityZoneProvisioning zoneDao;
    private final IdentityProviderProvisioning idpDao;
    private final IdentityZoneEndpointClientRegistrationService clientRegistrationService;
    

    public IdentityZoneEndpoints(IdentityZoneProvisioning zoneDao, IdentityProviderProvisioning idpDao,
            IdentityZoneEndpointClientRegistrationService clientRegistrationService) {
        super();
        this.zoneDao = zoneDao;
        this.idpDao = idpDao;
        this.clientRegistrationService = clientRegistrationService;
    }

    @RequestMapping(value = "{id}", method = GET)
    public IdentityZone getIdentityZone(@PathVariable String id) {
        return zoneDao.retrieve(id);
    }

    @RequestMapping(method = POST)
    public ResponseEntity<IdentityZone> createIdentityZone(@RequestBody @Valid IdentityZone body) {
        
        if (!StringUtils.hasText(body.getId())) {
            body.setId(UUID.randomUUID().toString());
        }
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            IdentityZone created = zoneDao.create(body);
            IdentityZoneHolder.set(created);
            IdentityProvider defaultIdp = new IdentityProvider();
            defaultIdp.setName("internal");
            defaultIdp.setType("internal");
            defaultIdp.setOriginKey(Origin.UAA);
            defaultIdp.setIdentityZoneId(created.getId());
            idpDao.create(defaultIdp);

            return new ResponseEntity<>(created, CREATED);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }

    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<IdentityZone> updateIdentityZone(
            @RequestBody @Valid IdentityZone body, @PathVariable String id) {
        
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            // make sure it exists
            zoneDao.retrieve(id);
            // ignore the id in the body, the id in the path is the only one that matters
            body.setId(id);
            IdentityZone updated = zoneDao.update(body);
            IdentityZoneHolder.set(updated);
            return new ResponseEntity<>(updated, OK);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }

    @RequestMapping(method = POST, value = "{identityZoneId}/clients")
    public ResponseEntity<? extends ClientDetails> createClient(
            @PathVariable String identityZoneId, @RequestBody BaseClientDetails clientDetails) {
        
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            IdentityZone identityZone = zoneDao.retrieve(identityZoneId);
            IdentityZoneHolder.set(identityZone);
            ClientDetails createdClient = clientRegistrationService.createClient(clientDetails);
            return new ResponseEntity<>(removeSecret(createdClient), CREATED);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }

    private ClientDetails removeSecret(ClientDetails createdClient) {
        BaseClientDetails response = (BaseClientDetails) createdClient;
        response.setClientSecret(null);
        return response;
    }
    
    @RequestMapping(method = DELETE, value = "{identityZoneId}/clients/{clientId}")
    public ResponseEntity<? extends ClientDetails> deleteClient(
            @PathVariable String identityZoneId, @PathVariable String clientId) {
        
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            IdentityZone identityZone = zoneDao.retrieve(identityZoneId);
            IdentityZoneHolder.set(identityZone);
            ClientDetails deleted = clientRegistrationService.deleteClient(clientId);
            
            return new ResponseEntity<>(removeSecret(deleted), OK);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }
    
    @ExceptionHandler(ZoneAlreadyExistsException.class)
    public ResponseEntity<ZoneAlreadyExistsException> handleZoneAlreadyExistsException(ZoneAlreadyExistsException e) {
        return new ResponseEntity<>(e, CONFLICT);
    }

    @ExceptionHandler(InvalidClientDetailsException.class)
    public ResponseEntity<InvalidClientDetailsException> handleInvalidClientDetails(InvalidClientDetailsException e) {
        return new ResponseEntity<InvalidClientDetailsException>(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NoSuchClientException.class)
    public ResponseEntity<Void> handleNoSuchClient(NoSuchClientException e) {
        return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(ClientAlreadyExistsException.class)
    public ResponseEntity<InvalidClientDetailsException> handleClientAlreadyExists(ClientAlreadyExistsException e) {
        return new ResponseEntity<InvalidClientDetailsException>(new InvalidClientDetailsException(e.getMessage()),
                        HttpStatus.CONFLICT);
    }

    @ExceptionHandler(ZoneDoesNotExistsException.class)
    public ResponseEntity<ZoneDoesNotExistsException> handleZoneDoesNotExistsException(ZoneDoesNotExistsException e) {
        return new ResponseEntity<>(NOT_FOUND);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Void> handleValidationException(MethodArgumentNotValidException e) {
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Void> handleAccessDeniedException(MethodArgumentNotValidException e) {
        return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> handleException(Exception e) {
        log.error(e.getClass() + ": " + e.getMessage(), e);
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
