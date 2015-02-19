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

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.oauth.ClientDetailsValidator;
import org.cloudfoundry.identity.uaa.oauth.InvalidClientDetailsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.web.bind.annotation.RequestMethod.*;

@RestController
@RequestMapping("/identity-zones")
public class IdentityZoneEndpoints {

    private static final Logger log = LoggerFactory.getLogger(IdentityZoneEndpoints.class);
    private final IdentityZoneProvisioning zoneDao;
    private final IdentityProviderProvisioning idpDao;
    private final ClientRegistrationService clientRegistrationService;
    private final ClientDetailsValidator clientDetailsValidator;
    
    
    public IdentityZoneEndpoints(IdentityZoneProvisioning zoneDao, IdentityProviderProvisioning idpDao, ClientRegistrationService clientRegistrationService, ClientDetailsValidator clientDetailsValidator) {
        super();
        this.zoneDao = zoneDao;
        this.idpDao = idpDao;
        this.clientRegistrationService = clientRegistrationService;
        this.clientDetailsValidator = clientDetailsValidator;
    }

    @RequestMapping(value="{id}", method = GET)
    public IdentityZone getIdentityZone(@PathVariable String id) {
        return zoneDao.retrieve(id);
    }
    
    @RequestMapping(method = POST)
    public ResponseEntity<IdentityZone> createIdentityZone(@RequestBody @Valid IdentityZoneCreationRequest body)
    {
        if (body.getIdentityZone()==null) {
            return new ResponseEntity<>(body.getIdentityZone(), HttpStatus.BAD_REQUEST);
        }
        if (!StringUtils.hasText(body.getIdentityZone().getId())) {
            body.getIdentityZone().setId(UUID.randomUUID().toString());
        }
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            List<ClientDetails> clients = new ArrayList<ClientDetails>();
            if (body.getClientDetails() != null) {
                for (BaseClientDetails clientDetails : body.getClientDetails()) {
                    if (clientDetails != null) {
                        clients.add(clientDetailsValidator.validate(clientDetails, true, false));
                    }
                }
            }
            IdentityZone created = zoneDao.create(body.getIdentityZone());
            IdentityZoneHolder.set(created);
            IdentityProvider defaultIdp = new IdentityProvider();
            defaultIdp.setName("internal");
            defaultIdp.setType("internal");
            defaultIdp.setOriginKey(Origin.UAA);
            idpDao.create(defaultIdp);

            for (ClientDetails validClient : clients) {
                clientRegistrationService.addClientDetails(validClient);
            }
            
            return new ResponseEntity<>(created,CREATED);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }

    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<IdentityZone> updateIdentityZone(
        @RequestBody @Valid IdentityZoneCreationRequest body,
        @PathVariable String id)
    {
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            zoneDao.retrieve(id);
            List<ClientDetails> clients = new ArrayList<ClientDetails>();
            if (body.getClientDetails() != null) {
                for (BaseClientDetails clientDetails : body.getClientDetails()) {
                    if (clientDetails != null) {
                        clients.add(clientDetailsValidator.validate(clientDetails, true, false));
                    }
                }
            }
            // ignore the id in the body, the id in the path is the only one that matters
            body.getIdentityZone().setId(id);
            IdentityZone updated = zoneDao.update(body.getIdentityZone());
            IdentityZoneHolder.set(updated);

            for (ClientDetails validClient : clients) {
                try {
                    clientRegistrationService.addClientDetails(validClient);
                } catch (ClientAlreadyExistsException x) {}
            }
            return new ResponseEntity<>(updated,OK);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }

    @ExceptionHandler(ZoneAlreadyExistsException.class)
    public ResponseEntity<ZoneAlreadyExistsException> handleZoneAlreadyExistsException(ZoneAlreadyExistsException e) {
        return new ResponseEntity<>(e,CONFLICT);
    }

    @ExceptionHandler(ZoneDoesNotExistsException.class)
    public ResponseEntity<ZoneDoesNotExistsException> handleZoneDoesNotExistsException(ZoneDoesNotExistsException e) {
        return new ResponseEntity<>(e,NOT_FOUND);
    }

    @ExceptionHandler(InvalidClientDetailsException.class)
    public ResponseEntity<InvalidClientDetailsException> handleInvalidClientDetails(InvalidClientDetailsException e) {
        return new ResponseEntity<>(e, HttpStatus.BAD_REQUEST);
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
        log.error(e.getClass()+": "+e.getMessage(),e);
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
