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
package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.Errors;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

@RestController
@RequestMapping("/identity-zones")
public class IdentityZoneEndpoints implements ApplicationEventPublisherAware {

    @Autowired
    private MessageSource messageSource;

    private ApplicationEventPublisher publisher;

    private static final Logger logger = LoggerFactory.getLogger(IdentityZoneEndpoints.class);
    private final IdentityZoneProvisioning zoneDao;
    private final IdentityProviderProvisioning idpDao;
    private final IdentityZoneEndpointClientRegistrationService clientRegistrationService;
    private final ScimGroupProvisioning groupProvisioning;

    private IdentityZoneValidator validator;

    public IdentityZoneEndpoints(IdentityZoneProvisioning zoneDao, IdentityProviderProvisioning idpDao,
                                 IdentityZoneEndpointClientRegistrationService clientRegistrationService,
                                 ScimGroupProvisioning groupProvisioning) {
        super();
        this.zoneDao = zoneDao;
        this.idpDao = idpDao;
        this.clientRegistrationService = clientRegistrationService;
        this.groupProvisioning = groupProvisioning;
    }

    public void setValidator(IdentityZoneValidator validator) {
        this.validator = validator;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }


    @RequestMapping(value = "{id}", method = GET)
    public IdentityZone getIdentityZone(@PathVariable String id) {
        List<IdentityZone> result = filterForCurrentZone(Arrays.asList(zoneDao.retrieveIgnoreActiveFlag(id)));
        if (result.size() == 0) {
            throw new ZoneDoesNotExistsException("Zone does not exist or is not accessible.");
        }
        return removeKeys(result.get(0));
    }

    protected IdentityZone removeKeys(IdentityZone identityZone) {
        if (identityZone.getConfig() != null && identityZone.getConfig().getTokenPolicy() != null) {
            identityZone.getConfig().getTokenPolicy().setKeys(null);
        }
        if (identityZone.getConfig() != null && identityZone.getConfig().getSamlConfig() != null) {
            identityZone.getConfig().getSamlConfig().setPrivateKeyPassword(null);
            identityZone.getConfig().getSamlConfig().setPrivateKey(null);
            identityZone.getConfig().getSamlConfig().getKeys().entrySet().forEach(
                entry -> {
                    entry.getValue().setPassphrase(null);
                    entry.getValue().setKey(null);
                }
            );
        }
        return identityZone;
    }

    @RequestMapping(method = GET)
    public List<IdentityZone> getIdentityZones() {
        return filterForCurrentZone(zoneDao.retrieveAll());
    }

    protected List<IdentityZone> filterForCurrentZone(List<IdentityZone> zones) {
        List<IdentityZone> result = new LinkedList<>();
        if (IdentityZoneHolder.isUaa()) {
            for (IdentityZone zone : zones) {
                result.add(removeKeys(zone));
            }
            return result;
        }
        String currentId = IdentityZoneHolder.get().getId();

        for (IdentityZone zone : zones) {
            if (currentId.equals(zone.getId())) {
                result.add(removeKeys(filterForZonesDotRead(zone)));
                break;
            }
        }

        return result;
    }

    protected IdentityZone filterForZonesDotRead(IdentityZone zone) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && hasReadOnlyAuthority(zone.getId(), auth)) {
            zone.getConfig().setSamlConfig(null);
            zone.getConfig().setTokenPolicy(null);
        }
        return zone;
    }

    protected boolean hasReadOnlyAuthority(String zoneId, Authentication authentication) {
        boolean hasRead = false;
        boolean doesNotHaveAdmin = true;
        String adminScope = ZoneManagementScopes.ZONES_ZONE_ID_PREFIX + zoneId + ".admin";
        String readScope = ZoneManagementScopes.ZONES_ZONE_ID_PREFIX + zoneId + ".read";
        for (GrantedAuthority a : authentication.getAuthorities()) {
            if (adminScope.equals(a.getAuthority())) {
                doesNotHaveAdmin = false;
            } else if (readScope.equals(a.getAuthority())) {
                hasRead = true;
            }
        }
        return hasRead && doesNotHaveAdmin;
    }


    @RequestMapping(method = POST)
    public ResponseEntity<IdentityZone> createIdentityZone(@RequestBody @Valid IdentityZone body, BindingResult result) {

        if (result.hasErrors()) {
            throw new UnprocessableEntityException(getErrorMessages(result));
        }

        if (!IdentityZoneHolder.isUaa()) {
            throw new AccessDeniedException("Zones can only be created by being authenticated in the default zone.");
        }

        try {
            body = validator.validate(body, IdentityZoneValidator.Mode.CREATE);
        } catch (InvalidIdentityZoneDetailsException ex) {
            String errorMessage = StringUtils.hasText(ex.getMessage())?ex.getMessage():"";
            throw new UnprocessableEntityException("The identity zone details are invalid. " + errorMessage, ex);
        }

        if (!StringUtils.hasText(body.getId())) {
            body.setId(UUID.randomUUID().toString());
        }
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            logger.debug("Zone - creating id[" + body.getId() + "] subdomain[" + body.getSubdomain() + "]");
            IdentityZone created = zoneDao.create(body);
            logger.debug("Zone - created id[" + created.getId() + "] subdomain[" + created.getSubdomain() + "]");
            IdentityZoneHolder.set(created);
            IdentityProvider defaultIdp = new IdentityProvider();
            defaultIdp.setName(OriginKeys.UAA);
            defaultIdp.setType(OriginKeys.UAA);
            defaultIdp.setOriginKey(OriginKeys.UAA);
            defaultIdp.setIdentityZoneId(created.getId());
            UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition();
            idpDefinition.setPasswordPolicy(null);
            defaultIdp.setConfig(idpDefinition);
            idpDao.create(defaultIdp, created.getId());
            logger.debug("Created default IDP in zone - created id[" + created.getId() + "] subdomain[" + created.getSubdomain() + "]");
            createUserGroups(created);
            return new ResponseEntity<>(removeKeys(created), CREATED);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }

    public void createUserGroups(IdentityZone zone) {
        UserConfig userConfig = zone.getConfig().getUserConfig();
        if (userConfig != null) {
            List<String> defaultGroups = ofNullable(userConfig.getDefaultGroups()).orElse(Collections.emptyList());
            logger.debug(String.format("About to create default groups count: %s for subdomain: %s", defaultGroups.size(), zone.getSubdomain()));
            for (String group : defaultGroups) {
                logger.debug(String.format("Creating zone default group: %s for subdomain: %s", group, zone.getSubdomain()));
                groupProvisioning.createOrGet(
                    new ScimGroup(
                        null,
                        group,
                        zone.getId()
                    ),
                    zone.getId()
                );
            }
        }
    }

    private String getErrorMessages(Errors errors) {
        List<String> messages = new ArrayList<>();
        for (ObjectError error : errors.getAllErrors()) {
            messages.add(messageSource.getMessage(error, Locale.getDefault()));
        }
        return String.join("\r\n", messages);
    }

    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<IdentityZone> updateIdentityZone(
        @RequestBody @Valid IdentityZone body, @PathVariable String id) {
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            if (id == null) {
                throw new ZoneDoesNotExistsException(id);
            }
            if (!IdentityZoneHolder.isUaa() && !id.equals(IdentityZoneHolder.get().getId())) {
                throw new AccessDeniedException("Zone admins can only update their own zone.");
            }

            if(body.getId() != null && !body.getId().equals(id)) {
                throw new UnprocessableEntityException("The identity zone id from the request body does not match id in the url");
            }

            // make sure it exists
            IdentityZone existingZone = zoneDao.retrieveIgnoreActiveFlag(id);
            restoreSecretProperties(existingZone, body);
            //validator require id to be present
            body.setId(id);
            body = validator.validate(body, IdentityZoneValidator.Mode.MODIFY);

            logger.debug("Zone - updating id[" + id + "] subdomain[" + body.getSubdomain() + "]");
            IdentityZone updated = zoneDao.update(body);
            IdentityZoneHolder.set(updated);
            logger.debug("Zone - updated id[" + updated.getId() + "] subdomain[" + updated.getSubdomain() + "]");
            createUserGroups(updated);
            return new ResponseEntity<>(removeKeys(updated), OK);
        } catch (InvalidIdentityZoneDetailsException ex) {
            String errorMessage = StringUtils.hasText(ex.getMessage())?ex.getMessage():"";
            throw new UnprocessableEntityException("The identity zone details are invalid. " + errorMessage, ex);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }


    protected void restoreSecretProperties(IdentityZone existingZone, IdentityZone newZone) {
        if (newZone.getConfig() != null) {
            if (newZone.getConfig().getTokenPolicy() != null) {
                if (newZone.getConfig().getTokenPolicy().getKeys() == null || newZone.getConfig().getTokenPolicy().getKeys().isEmpty()) {
                    newZone.getConfig().getTokenPolicy().setKeys(existingZone.getConfig().getTokenPolicy().getKeys());
                }
            }
            if (newZone.getConfig().getSamlConfig() != null) {
                SamlConfig config = newZone.getConfig().getSamlConfig();
                SamlConfig oldConfig = existingZone.getConfig().getSamlConfig();
                for (Map.Entry<String, SamlKey> entry : config.getKeys().entrySet()) {
                    SamlKey original = oldConfig.getKeys().get(entry.getKey());
                    if (entry.getValue().getKey() == null &&
                        entry.getValue().getPassphrase() == null &&
                        original != null &&
                        original.getCertificate() != null &&
                        original.getCertificate().equals(entry.getValue().getCertificate())) {
                        entry.getValue().setKey(original.getKey());
                        entry.getValue().setPassphrase(original.getPassphrase());
                    }
                }
            }
        }
    }

    @RequestMapping(value = "{id}", method = DELETE)
    @Transactional
    public ResponseEntity<IdentityZone> deleteIdentityZone(@PathVariable String id) {
        if (id == null) {
            throw new ZoneDoesNotExistsException(id);
        }
        if (!IdentityZoneHolder.isUaa() && !id.equals(IdentityZoneHolder.get().getId())) {
            throw new AccessDeniedException("Zone admins can only update their own zone.");
        }
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            logger.debug("Zone - deleting id[" + id + "]");
            // make sure it exists
            IdentityZone zone = zoneDao.retrieveIgnoreActiveFlag(id);
            // ignore the id in the body, the id in the path is the only one that matters
            IdentityZoneHolder.set(zone);
            if (publisher != null && zone != null) {
                publisher.publishEvent(new EntityDeletedEvent<>(zone, SecurityContextHolder.getContext().getAuthentication(), IdentityZoneHolder.getCurrentZoneId()));
                logger.debug("Zone - deleted id[" + zone.getId() + "]");
                return new ResponseEntity<>(removeKeys(zone), OK);
            } else {
                return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
            }
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }

    @RequestMapping(method = POST, value = "{identityZoneId}/clients")
    public ResponseEntity<? extends ClientDetails> createClient(
        @PathVariable String identityZoneId, @RequestBody BaseClientDetails clientDetails) {
        if (identityZoneId == null) {
            throw new ZoneDoesNotExistsException(identityZoneId);
        }
        if (!IdentityZoneHolder.isUaa() && !identityZoneId.equals(IdentityZoneHolder.get().getId())) {
            throw new AccessDeniedException("Zone admins can only create clients in their own zone.");
        }
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            logger.debug("Zone creating client zone[" + identityZoneId + "] client[" + clientDetails.getClientId() + "]");
            IdentityZone identityZone = zoneDao.retrieve(identityZoneId);
            IdentityZoneHolder.set(identityZone);
            ClientDetails createdClient = clientRegistrationService.createClient(clientDetails);
            logger.debug("Zone client created zone[" + identityZoneId + "] client[" + clientDetails.getClientId() + "]");
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
        if (identityZoneId == null) {
            throw new ZoneDoesNotExistsException(identityZoneId);
        }
        if (!IdentityZoneHolder.isUaa() && !identityZoneId.equals(IdentityZoneHolder.get().getId())) {
            throw new AccessDeniedException("Zone admins can only delete their own zone.");
        }
        IdentityZone previous = IdentityZoneHolder.get();
        try {
            logger.debug("Zone deleting client zone[" + identityZoneId + "] client[" + clientId + "]");
            IdentityZone identityZone = zoneDao.retrieve(identityZoneId);
            IdentityZoneHolder.set(identityZone);
            ClientDetails deleted = clientRegistrationService.deleteClient(clientId);
            logger.debug("Zone client deleted zone[" + identityZoneId + "] client[" + clientId + "]");
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
        return new ResponseEntity<>(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NoSuchClientException.class)
    public ResponseEntity<Void> handleNoSuchClient(NoSuchClientException e) {
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(ClientAlreadyExistsException.class)
    public ResponseEntity<InvalidClientDetailsException> handleClientAlreadyExists(ClientAlreadyExistsException e) {
        return new ResponseEntity<>(new InvalidClientDetailsException(e.getMessage()),
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
    public ResponseEntity<Void> handleAccessDeniedException(AccessDeniedException e) {
        return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(UnprocessableEntityException.class)
    public ResponseEntity<UnprocessableEntityException> handleUnprocessableEntityException(UnprocessableEntityException e) {
        return new ResponseEntity<>(e, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> handleException(Exception e) {
        logger.error(e.getClass() + ": " + e.getMessage(), e);
        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private class UnprocessableEntityException extends UaaException {
        public UnprocessableEntityException(String message) {
            super("invalid_identity_zone", message, 422);
        }

        public UnprocessableEntityException(String message, Throwable cause) {
            super(cause, "invalid_identity_zone", message, 422);
        }
    }
}
