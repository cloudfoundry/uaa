/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicLdapAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LdapLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.EXPECTATION_FAILED;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

@RequestMapping("/identity-providers")
@RestController
public class IdentityProviderEndpoints implements ApplicationEventPublisherAware {

    protected static Log logger = LogFactory.getLog(IdentityProviderEndpoints.class);

    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private final ScimGroupProvisioning scimGroupProvisioning;
    private final NoOpLdapLoginAuthenticationManager noOpManager = new NoOpLdapLoginAuthenticationManager();
    private final SamlIdentityProviderConfigurator samlConfigurator;
    private final IdentityProviderConfigValidationDelegator configValidator;
    private ApplicationEventPublisher publisher = null;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public IdentityProviderEndpoints(
        IdentityProviderProvisioning identityProviderProvisioning,
        ScimGroupExternalMembershipManager scimGroupExternalMembershipManager,
        ScimGroupProvisioning scimGroupProvisioning,
        SamlIdentityProviderConfigurator samlConfigurator,
        IdentityProviderConfigValidationDelegator configValidator) {
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.scimGroupExternalMembershipManager = scimGroupExternalMembershipManager;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.samlConfigurator = samlConfigurator;
        this.configValidator = configValidator;
    }

    @RequestMapping(method = POST)
    public ResponseEntity<IdentityProvider> createIdentityProvider(@RequestBody IdentityProvider body, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) throws MetadataProviderException{
        body.setSerializeConfigRaw(rawConfig);
        String zoneId = IdentityZoneHolder.get().getId();
        body.setIdentityZoneId(zoneId);
        try {
            configValidator.validate(body.getConfig(), body.getType());
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        if (OriginKeys.SAML.equals(body.getType())) {
            SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(body.getConfig(), SamlIdentityProviderDefinition.class);
            definition.setZoneId(zoneId);
            definition.setIdpEntityAlias(body.getOriginKey());
            samlConfigurator.addSamlIdentityProviderDefinition(definition);
            body.setConfig(definition);
        }
        try {
            IdentityProvider createdIdp = identityProviderProvisioning.create(body);
            createdIdp.setSerializeConfigRaw(rawConfig);
            return new ResponseEntity<>(createdIdp, CREATED);
        } catch (IdpAlreadyExistsException e) {
            return new ResponseEntity<>(body, CONFLICT);
        } catch (Exception x) {
            logger.debug("Unable to create IdentityProvider["+x.getMessage()+"].", x);
            return new ResponseEntity<>(body, INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(value = "{id}", method = DELETE)
    @Transactional
    public ResponseEntity<IdentityProvider> deleteIdentityProvider(@PathVariable String id, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) throws MetadataProviderException {
        IdentityProvider existing = identityProviderProvisioning.retrieve(id);
        if (publisher!=null && existing!=null) {
            existing.setSerializeConfigRaw(rawConfig);
            publisher.publishEvent(new EntityDeletedEvent<>(existing, SecurityContextHolder.getContext().getAuthentication()));
            return new ResponseEntity<>(existing, OK);
        } else {
            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
        }
    }


    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<IdentityProvider> updateIdentityProvider(@PathVariable String id, @RequestBody IdentityProvider body, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) throws MetadataProviderException {
        body.setSerializeConfigRaw(rawConfig);
        IdentityProvider existing = identityProviderProvisioning.retrieve(id);
        String zoneId = IdentityZoneHolder.get().getId();
        body.setId(id);
        body.setIdentityZoneId(zoneId);
        try {
            configValidator.validate(body.getConfig(), body.getType());
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        if (OriginKeys.SAML.equals(body.getType())) {
            body.setOriginKey(existing.getOriginKey()); //we do not allow origin to change for a SAML provider, since that can cause clashes
            SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(body.getConfig(), SamlIdentityProviderDefinition.class);
            definition.setZoneId(zoneId);
            definition.setIdpEntityAlias(body.getOriginKey());
            samlConfigurator.addSamlIdentityProviderDefinition(definition);
            body.setConfig(definition);
        }
        IdentityProvider updatedIdp = identityProviderProvisioning.update(body);
        updatedIdp.setSerializeConfigRaw(rawConfig);
        return new ResponseEntity<>(updatedIdp, OK);
    }

    @RequestMapping(method = GET)
    public ResponseEntity<List<IdentityProvider>> retrieveIdentityProviders(@RequestParam(value = "active_only", required = false) String activeOnly, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        Boolean retrieveActiveOnly = Boolean.valueOf(activeOnly);
        List<IdentityProvider> identityProviderList = identityProviderProvisioning.retrieveAll(retrieveActiveOnly, IdentityZoneHolder.get().getId());
        for(IdentityProvider idp : identityProviderList) {
            idp.setSerializeConfigRaw(rawConfig);
        }
        return new ResponseEntity<>(identityProviderList, OK);
    }

    @RequestMapping(value = "{id}", method = GET)
    public ResponseEntity<IdentityProvider> retrieveIdentityProvider(@PathVariable String id, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieve(id);
        identityProvider.setSerializeConfigRaw(rawConfig);
        return new ResponseEntity<>(identityProvider, OK);
    }

    @RequestMapping(value = "test", method = POST)
    public ResponseEntity<String> testIdentityProvider(@RequestBody IdentityProviderValidationRequest body) {
        String exception = "ok";
        HttpStatus status = OK;
        //create the LDAP IDP
        DynamicLdapAuthenticationManager manager = new DynamicLdapAuthenticationManager(
            ObjectUtils.castInstance(body.getProvider().getConfig(),LdapIdentityProviderDefinition.class),
            scimGroupExternalMembershipManager,
            scimGroupProvisioning,
            noOpManager
        );
        try {
            //attempt authentication
            Authentication result = manager.authenticate(body.getCredentials());
            if ((result == null) || (result != null && !result.isAuthenticated())) {
                status = EXPECTATION_FAILED;
            }
        } catch (BadCredentialsException x) {
            status = EXPECTATION_FAILED;
            exception = "bad credentials";
        } catch (InternalAuthenticationServiceException x) {
            status = BAD_REQUEST;
            exception = getExceptionString(x);
        } catch (Exception x) {
            logger.debug("Identity provider validation failed.", x);
            status = INTERNAL_SERVER_ERROR;
            exception = "check server logs";
        }finally {
            //destroy IDP
            manager.destroy();
        }
        //return results
        return new ResponseEntity<>(JsonUtils.writeValueAsString(exception), status);
    }


    @ExceptionHandler(MetadataProviderException.class)
    public ResponseEntity<String> handleMetadataProviderException(MetadataProviderException e) {
        if (e.getMessage().contains("Duplicate")) {
            return new ResponseEntity<>(e.getMessage(), CONFLICT);
        } else {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @ExceptionHandler(JsonUtils.JsonUtilException.class)
    public ResponseEntity<String> handleMetadataProviderException() {
        return new ResponseEntity<>("Invalid provider configuration.", HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(EmptyResultDataAccessException.class)
    public ResponseEntity<String> handleProviderNotFoundException() {
        return new ResponseEntity<>("Provider not found.", HttpStatus.NOT_FOUND);
    }


    protected String getExceptionString(Exception x) {
        StringWriter writer = new StringWriter();
        x.printStackTrace(new PrintWriter(writer));
        return writer.getBuffer().toString();
    }

    protected static class NoOpLdapLoginAuthenticationManager extends LdapLoginAuthenticationManager {
        @Override
        public Authentication authenticate(Authentication request) throws AuthenticationException {
            return request;
        }
    }
}
