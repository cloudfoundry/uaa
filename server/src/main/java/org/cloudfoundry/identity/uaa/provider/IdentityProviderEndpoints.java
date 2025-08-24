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

import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicLdapAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LdapLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getCleanedUserControlString;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.EXPECTATION_FAILED;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.util.StringUtils.hasText;

@RequestMapping("/identity-providers")
@RestController
public class IdentityProviderEndpoints implements ApplicationEventPublisherAware {

    protected static Logger logger = LoggerFactory.getLogger(IdentityProviderEndpoints.class);

    private final boolean aliasEntitiesEnabled;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private final ScimGroupProvisioning scimGroupProvisioning;
    private final NoOpLdapLoginAuthenticationManager noOpManager = new NoOpLdapLoginAuthenticationManager();
    private final SamlIdentityProviderConfigurator samlConfigurator;
    private final IdentityProviderConfigValidator configValidator;
    private final IdentityZoneManager identityZoneManager;
    private final TransactionTemplate transactionTemplate;
    private final IdentityProviderAliasHandler idpAliasHandler;

    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public IdentityProviderEndpoints(
            final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning identityProviderProvisioning,
            final @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager scimGroupExternalMembershipManager,
            final @Qualifier("scimGroupProvisioning") ScimGroupProvisioning scimGroupProvisioning,
            final @Qualifier("metaDataProviders") SamlIdentityProviderConfigurator samlConfigurator,
            final @Qualifier("identityProviderConfigValidator") IdentityProviderConfigValidator configValidator,
            final IdentityZoneManager identityZoneManager,
            final @Qualifier("transactionManager") PlatformTransactionManager transactionManager,
            final IdentityProviderAliasHandler idpAliasHandler,
            final @Qualifier("aliasEntitiesEnabled") boolean aliasEntitiesEnabled
    ) {
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.scimGroupExternalMembershipManager = scimGroupExternalMembershipManager;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.samlConfigurator = samlConfigurator;
        this.configValidator = configValidator;
        this.identityZoneManager = identityZoneManager;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.idpAliasHandler = idpAliasHandler;
        this.aliasEntitiesEnabled = aliasEntitiesEnabled;
    }

    @PostMapping({"/", ""})
    public ResponseEntity<IdentityProvider> createIdentityProvider(@RequestBody IdentityProvider body, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        body.setSerializeConfigRaw(rawConfig);
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        body.setIdentityZoneId(zoneId);
        try {
            configValidator.validate(body);
        } catch (IllegalArgumentException e) {
            logger.debug("IdentityProvider[origin=%s; zone=%s] - Configuration validation error.".formatted(body.getOriginKey(), body.getIdentityZoneId()), e);
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        if (SAML.equals(body.getType())) {
            SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(body.getConfig(), SamlIdentityProviderDefinition.class);
            definition.setZoneId(zoneId);
            definition.setIdpEntityAlias(body.getOriginKey());
            definition.setIdpEntityId(samlConfigurator.validateSamlIdentityProviderDefinition(definition, true));
            body.setConfig(definition);
        }

        if (!idpAliasHandler.aliasPropertiesAreValid(body, null)) {
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }

        // persist IdP and create alias if necessary
        return persistIdentityProviderChange(body, rawConfig, zoneId, null, CREATED);
    }

    @DeleteMapping(value = "{id}")
    @Transactional
    public ResponseEntity<IdentityProvider> deleteIdentityProvider(@PathVariable String id, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        String identityZoneId = identityZoneManager.getCurrentIdentityZoneId();
        IdentityProvider<?> existing = identityProviderProvisioning.retrieve(id, identityZoneId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (publisher == null || existing == null) {
            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
        }

        // reject deletion if the IdP has an alias, but alias feature is disabled
        final boolean idpHasAlias = hasText(existing.getAliasZid());
        if (idpHasAlias && !aliasEntitiesEnabled) {
            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
        }

        // delete the IdP
        existing.setSerializeConfigRaw(rawConfig);
        publisher.publishEvent(new EntityDeletedEvent<>(existing, authentication, identityZoneId));
        setAuthMethod(existing);
        redactSensitiveData(existing);

        // delete the alias IdP if present
        if (idpHasAlias) {
            final Optional<IdentityProvider<?>> aliasIdpOpt = idpAliasHandler.retrieveAliasEntity(existing);
            if (aliasIdpOpt.isEmpty()) {
                // ignore dangling reference to alias
                logger.warn(
                        "Alias IdP referenced in IdentityProvider[origin={}; zone={}}] not found, skipping deletion of alias IdP.",
                        existing.getOriginKey(),
                        existing.getIdentityZoneId()
                );
                return new ResponseEntity<>(existing, OK);
            }

            final IdentityProvider<?> aliasIdp = aliasIdpOpt.get();
            aliasIdp.setSerializeConfigRaw(rawConfig);
            publisher.publishEvent(new EntityDeletedEvent<>(aliasIdp, authentication, identityZoneId));
        }

        return new ResponseEntity<>(existing, OK);
    }

    @PutMapping(value = "{id}")
    public ResponseEntity<IdentityProvider> updateIdentityProvider(@PathVariable String id, @RequestBody IdentityProvider body, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        body.setSerializeConfigRaw(rawConfig);
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        IdentityProvider existing = identityProviderProvisioning.retrieve(id, zoneId);
        body.setId(id);
        body.setIdentityZoneId(zoneId);
        patchSensitiveData(id, body);
        try {
            configValidator.validate(body);
        } catch (IllegalArgumentException e) {
            logger.debug("IdentityProvider[origin=%s; zone=%s] - Configuration validation error for update.".formatted(body.getOriginKey(), body.getIdentityZoneId()), e);
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }

        if (!idpAliasHandler.aliasPropertiesAreValid(body, existing)) {
            if (logger.isWarnEnabled()) {
                logger.warn("IdentityProvider[origin={}; zone={}] - Alias ID and/or ZID changed during update of IdP with alias.",
                        getCleanedUserControlString(body.getOriginKey()), getCleanedUserControlString(body.getIdentityZoneId()));
            }
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }

        if (SAML.equals(body.getType())) {
            body.setOriginKey(existing.getOriginKey()); //we do not allow origin to change for a SAML provider, since that can cause clashes
            SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(body.getConfig(), SamlIdentityProviderDefinition.class);
            definition.setZoneId(zoneId);
            definition.setIdpEntityAlias(body.getOriginKey());
            definition.setIdpEntityId(samlConfigurator.validateSamlIdentityProviderDefinition(definition, false));
            body.setConfig(definition);
        }

        return persistIdentityProviderChange(body, rawConfig, zoneId, existing, OK);
    }

    private ResponseEntity<IdentityProvider> persistIdentityProviderChange(IdentityProvider body, boolean rawConfig, String zoneId,
            IdentityProvider existing, HttpStatus status) {
        final IdentityProvider<?> updatedIdp;
        try {
            updatedIdp = transactionTemplate.execute(txStatus -> {
                final IdentityProvider<?> updatedOriginalIdp = status == CREATED ? identityProviderProvisioning.create(body, zoneId) : identityProviderProvisioning.update(body, zoneId);
                return idpAliasHandler.ensureConsistencyOfAliasEntity(updatedOriginalIdp, existing);
            });
        } catch (final IdpAlreadyExistsException e) {
            return new ResponseEntity<>(body, CONFLICT);
        } catch (final EntityAliasFailedException e) {
            logger.warn("Could not create alias for %s".formatted(e.getMessage()));
            final HttpStatus responseCode = Optional.ofNullable(HttpStatus.resolve(e.getHttpStatus())).orElse(INTERNAL_SERVER_ERROR);
            return new ResponseEntity<>(body, responseCode);
        } catch (final Exception e) {
            logger.warn("Unable to %s IdentityProvider[origin=%s; zone=%s]".formatted(
                    status == CREATED ? "create" : "update", body.getOriginKey(), body.getIdentityZoneId()), e);
            return new ResponseEntity<>(body, INTERNAL_SERVER_ERROR);
        }
        if (updatedIdp == null) {
            if (logger.isWarnEnabled()) {
                logger.warn(
                        "IdentityProvider[origin={}; zone={}] - Transaction {} IdP (and alias IdP, if applicable) was not successful, but no exception was thrown.",
                        getCleanedUserControlString(body.getOriginKey()), getCleanedUserControlString(body.getIdentityZoneId()),
                        status == CREATED ? "creating" : "updating");
            }
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        updatedIdp.setSerializeConfigRaw(rawConfig);
        setAuthMethod(updatedIdp);
        redactSensitiveData(updatedIdp);

        return new ResponseEntity<>(updatedIdp, status);
    }

    @PatchMapping(value = "{id}/status")
    public ResponseEntity<IdentityProviderStatus> updateIdentityProviderStatus(@PathVariable String id, @RequestBody IdentityProviderStatus body) {
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        IdentityProvider existing = identityProviderProvisioning.retrieve(id, zoneId);
        if (body.getRequirePasswordChange() == null || !body.getRequirePasswordChange()) {
            logger.debug("Invalid payload. The property requirePasswordChangeRequired needs to be set");
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        if (!UAA.equals(existing.getType())) {
            logger.debug("Invalid operation. This operation is not supported on external IDP");
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        UaaIdentityProviderDefinition uaaIdentityProviderDefinition = ObjectUtils.castInstance(existing.getConfig(), UaaIdentityProviderDefinition.class);
        if (uaaIdentityProviderDefinition == null || uaaIdentityProviderDefinition.getPasswordPolicy() == null) {
            logger.debug("IDP does not have an existing PasswordPolicy. Operation not supported");
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        uaaIdentityProviderDefinition.getPasswordPolicy().setPasswordNewerThan(new Date(System.currentTimeMillis()));
        identityProviderProvisioning.update(existing, zoneId);
        logger.info("PasswordChangeRequired property set for Identity Provider: {}", existing.getId());

        /* since this operation is only allowed for IdPs of type "UAA" and aliases are not supported for "UAA" IdPs,
         * we do not need to propagate the changes to an alias IdP here. */

        logger.info("PasswordChangeRequired property set for Identity Provider: {}", existing.getId());
        return new ResponseEntity<>(body, OK);
    }

    @GetMapping({"/", ""})
    public ResponseEntity<List<IdentityProvider>> retrieveIdentityProviders(
            @RequestParam(value = "active_only", required = false) String activeOnly,
            @RequestParam(required = false, defaultValue = "false") boolean rawConfig,
            @RequestParam(required = false, defaultValue = "") String originKey) {
        boolean retrieveActiveOnly = Boolean.parseBoolean(activeOnly);
        List<IdentityProvider> identityProviderList;
        if (UaaStringUtils.isNotEmpty(originKey)) {
            identityProviderList = List.of(identityProviderProvisioning.retrieveByOrigin(originKey, identityZoneManager.getCurrentIdentityZoneId()));
        } else {
            identityProviderList = identityProviderProvisioning.retrieveAll(retrieveActiveOnly, identityZoneManager.getCurrentIdentityZoneId());
        }
        for (IdentityProvider<?> idp : identityProviderList) {
            idp.setSerializeConfigRaw(rawConfig);
            setAuthMethod(idp);
            redactSensitiveData(idp);
        }
        return new ResponseEntity<>(identityProviderList, OK);
    }

    @GetMapping(value = "{id}")
    public ResponseEntity<IdentityProvider> retrieveIdentityProvider(@PathVariable String id, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieve(id, identityZoneManager.getCurrentIdentityZoneId());
        identityProvider.setSerializeConfigRaw(rawConfig);
        setAuthMethod(identityProvider);
        redactSensitiveData(identityProvider);
        return new ResponseEntity<>(identityProvider, OK);
    }

    @PostMapping(value = "test")
    public ResponseEntity<String> testIdentityProvider(@RequestBody IdentityProviderValidationRequest body) {
        String exception = "ok";
        HttpStatus status = OK;
        //create the LDAP IDP
        DynamicLdapAuthenticationManager manager = new DynamicLdapAuthenticationManager(
                ObjectUtils.castInstance(body.getProvider().getConfig(), LdapIdentityProviderDefinition.class),
                scimGroupExternalMembershipManager,
                scimGroupProvisioning,
                noOpManager
        );
        try {
            //attempt authentication
            Authentication result = manager.authenticate(body.getCredentials());
            if ((result == null) || (!result.isAuthenticated())) {
                status = EXPECTATION_FAILED;
            }
        } catch (BadCredentialsException x) {
            status = EXPECTATION_FAILED;
            exception = "bad credentials";
        } catch (InternalAuthenticationServiceException x) {
            status = BAD_REQUEST;
            exception = getExceptionString(x);
        } catch (Exception x) {
            logger.error("Identity provider validation failed.", x);
            status = INTERNAL_SERVER_ERROR;
            exception = "check server logs";
        } finally {
            //destroy IDP
            manager.destroy();
        }
        //return results
        return new ResponseEntity<>(JsonUtils.writeValueAsString(exception), status);
    }

    @ExceptionHandler(IdpAlreadyExistsException.class)
    public ResponseEntity<String> handleDuplicateEntry(IdpAlreadyExistsException e) {
        return new ResponseEntity<>(e.getMessage(), CONFLICT);
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
        public NoOpLdapLoginAuthenticationManager() {
            super(null);
        }

        @Override
        public Authentication authenticate(Authentication request) throws AuthenticationException {
            return request;
        }
    }

    protected void patchSensitiveData(String id, IdentityProvider provider) {
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        if (provider.getConfig() == null) {
            return;
        }
        switch (provider.getType()) {
            case LDAP: {
                if (provider.getConfig() instanceof LdapIdentityProviderDefinition definition && definition.getBindPassword() == null) {
                    IdentityProvider existing = identityProviderProvisioning.retrieve(id, zoneId);
                    if (existing != null &&
                            existing.getConfig() != null &&
                            existing.getConfig() instanceof LdapIdentityProviderDefinition existingDefinition) {
                        definition.setBindPassword(existingDefinition.getBindPassword());
                    }
                }
                break;
            }
            case OAUTH20, OIDC10: {
                if (provider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition definition &&
                        definition.getRelyingPartySecret() == null &&
                        secretNeeded(definition)) {
                    IdentityProvider existing = identityProviderProvisioning.retrieve(id, zoneId);
                    if (existing != null &&
                            existing.getConfig() != null &&
                            existing.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition existingDefinition) {
                        definition.setRelyingPartySecret(existingDefinition.getRelyingPartySecret());
                    }
                }
                break;
            }
            default:
                break;

        }
    }

    protected void redactSensitiveData(IdentityProvider provider) {
        if (provider.getConfig() == null) {
            return;
        }
        switch (provider.getType()) {
            case LDAP: {
                if (provider.getConfig() instanceof LdapIdentityProviderDefinition definition) {
                    logger.debug("Removing bind password from LDAP provider id: {}", provider.getId());
                    definition.setBindPassword(null);
                }
                break;
            }
            case OAUTH20, OIDC10: {
                if (provider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition<?> definition) {
                    logger.debug("Removing relying secret from OAuth/OIDC provider id: {}", provider.getId());
                    definition.setRelyingPartySecret(null);
                }
                break;
            }
            default:
                break;

        }
    }

    protected boolean secretNeeded(AbstractExternalOAuthIdentityProviderDefinition abstractExternalOAuthIdentityProviderDefinition) {
        boolean needSecret = true;
        if (abstractExternalOAuthIdentityProviderDefinition.getAuthMethod() != null) {
            return ClientAuthentication.secretNeeded(abstractExternalOAuthIdentityProviderDefinition.getAuthMethod());
        }
        return needSecret;
    }

    protected void setAuthMethod(IdentityProvider<?> provider) {
        if (provider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition<?> definition) {
            definition.setAuthMethod(ExternalOAuthIdentityProviderConfigValidator.getAuthMethod(definition));
        }
    }

}
