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

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.provider.IdpAliasFailedException.Reason.ALIAS_ZONE_DOES_NOT_EXIST;
import static org.cloudfoundry.identity.uaa.provider.IdpAliasFailedException.Reason.COULD_NOT_BREAK_REFERENCE_TO_ALIAS;
import static org.cloudfoundry.identity.uaa.provider.IdpAliasFailedException.Reason.ORIGIN_KEY_ALREADY_USED_IN_ALIAS_ZONE;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getCleanedUserControlString;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.EXPECTATION_FAILED;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.PATCH;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicLdapAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LdapLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
//import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/identity-providers")
@RestController
public class IdentityProviderEndpoints implements ApplicationEventPublisherAware {

    protected static Logger logger = LoggerFactory.getLogger(IdentityProviderEndpoints.class);

    /**
     * The IdP types for which alias IdPs (via 'aliasId' and 'aliasZid') are supported.
     */
    private static final Set<String> IDP_TYPES_ALIAS_SUPPORTED = Set.of(SAML, OAUTH20, OIDC10);

    @Value("${login.aliasEntitiesEnabled:false}")
    private boolean aliasEntitiesEnabled;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private final ScimGroupProvisioning scimGroupProvisioning;
    private final NoOpLdapLoginAuthenticationManager noOpManager = new NoOpLdapLoginAuthenticationManager();
    private final SamlIdentityProviderConfigurator samlConfigurator;
    private final IdentityProviderConfigValidator configValidator;
    private final IdentityZoneManager identityZoneManager;
    private final IdentityZoneProvisioning identityZoneProvisioning;
    private final TransactionTemplate transactionTemplate;

    private ApplicationEventPublisher publisher = null;

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
            final @Qualifier("identityZoneProvisioning") IdentityZoneProvisioning identityZoneProvisioning,
            final @Qualifier("transactionManager") PlatformTransactionManager transactionManager
    ) {
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.scimGroupExternalMembershipManager = scimGroupExternalMembershipManager;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.samlConfigurator = samlConfigurator;
        this.configValidator = configValidator;
        this.identityZoneManager = identityZoneManager;
        this.identityZoneProvisioning = identityZoneProvisioning;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @RequestMapping(method = POST)
    public ResponseEntity<IdentityProvider> createIdentityProvider(@RequestBody IdentityProvider body, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) /* throws MetadataProviderException */ {
        body.setSerializeConfigRaw(rawConfig);
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        body.setIdentityZoneId(zoneId);
        try {
            configValidator.validate(body);
        } catch (IllegalArgumentException e) {
            logger.debug("IdentityProvider[origin="+body.getOriginKey()+"; zone="+body.getIdentityZoneId()+"] - Configuration validation error.", e);
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        if (SAML.equals(body.getType())) {
            SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(body.getConfig(), SamlIdentityProviderDefinition.class);
            definition.setZoneId(zoneId);
            definition.setIdpEntityAlias(body.getOriginKey());
            samlConfigurator.validateSamlIdentityProviderDefinition(definition);
            body.setConfig(definition);
        }

        if (!aliasPropertiesAreValid(body, null)) {
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }

        // persist IdP and create alias if necessary
        final IdentityProvider<?> createdIdp;
        try {
            createdIdp = transactionTemplate.execute(txStatus -> {
                final IdentityProvider<?> createdOriginalIdp = identityProviderProvisioning.create(body, zoneId);
                return ensureConsistencyOfAliasIdp(createdOriginalIdp, null);
            });
        } catch (final IdpAlreadyExistsException e) {
            return new ResponseEntity<>(body, CONFLICT);
        } catch (final IdpAliasFailedException e) {
            logger.warn("Could not create alias for {}", e.getMessage());
            final HttpStatus responseCode = Optional.ofNullable(HttpStatus.resolve(e.getHttpStatus())).orElse(INTERNAL_SERVER_ERROR);
            return new ResponseEntity<>(body, responseCode);
        } catch (final Exception e) {
            logger.warn("Unable to create IdentityProvider[origin=" + body.getOriginKey() + "; zone=" + body.getIdentityZoneId() + "]", e);
            return new ResponseEntity<>(body, INTERNAL_SERVER_ERROR);
        }
        if (createdIdp == null) {
            logger.warn(
                    "IdentityProvider[origin={}; zone={}] - Transaction creating IdP (and alias IdP, if applicable) was not successful, but no exception was thrown.",
                    getCleanedUserControlString(body.getOriginKey()),
                    getCleanedUserControlString(body.getIdentityZoneId())
            );
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        createdIdp.setSerializeConfigRaw(rawConfig);
        redactSensitiveData(createdIdp);

        return new ResponseEntity<>(createdIdp, CREATED);
    }

    @RequestMapping(value = "{id}", method = DELETE)
    @Transactional
    public ResponseEntity<IdentityProvider> deleteIdentityProvider(@PathVariable String id, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        String identityZoneId = identityZoneManager.getCurrentIdentityZoneId();
        IdentityProvider<?> existing = identityProviderProvisioning.retrieve(id, identityZoneId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (publisher == null || existing == null) {
            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
        }

        existing.setSerializeConfigRaw(rawConfig);
        publisher.publishEvent(new EntityDeletedEvent<>(existing, authentication, identityZoneId));
        redactSensitiveData(existing);

        if (hasText(existing.getAliasZid()) && hasText(existing.getAliasId())) {
            final IdentityProvider<?> aliasIdp = retrieveAliasIdp(existing);
            if (aliasIdp == null) {
                // ignore dangling reference to alias
                logger.warn(
                        "Alias IdP referenced in IdentityProvider[origin={}; zone={}}] not found, skipping deletion of alias IdP.",
                        existing.getOriginKey(),
                        existing.getIdentityZoneId()
                );
                return new ResponseEntity<>(existing, OK);
            }

            if (!aliasEntitiesEnabled) {
                // if alias entities are not enabled, just break the reference
                aliasIdp.setAliasId(null);
                aliasIdp.setAliasZid(null);
                identityProviderProvisioning.update(aliasIdp, aliasIdp.getIdentityZoneId());

                return new ResponseEntity<>(existing, OK);
            }

            // also delete the alias IdP
            aliasIdp.setSerializeConfigRaw(rawConfig);
            publisher.publishEvent(new EntityDeletedEvent<>(aliasIdp, authentication, identityZoneId));
        }

        return new ResponseEntity<>(existing, OK);
    }

    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<IdentityProvider> updateIdentityProvider(@PathVariable String id, @RequestBody IdentityProvider body, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) /* throws MetadataProviderException */ {
        body.setSerializeConfigRaw(rawConfig);
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        IdentityProvider existing = identityProviderProvisioning.retrieve(id, zoneId);
        body.setId(id);
        body.setIdentityZoneId(zoneId);
        patchSensitiveData(id, body);
        try {
            configValidator.validate(body);
        } catch (IllegalArgumentException e) {
            logger.debug("IdentityProvider[origin="+body.getOriginKey()+"; zone="+body.getIdentityZoneId()+"] - Configuration validation error for update.", e);
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }

        if (!aliasPropertiesAreValid(body, existing)) {
            logger.warn(
                    "IdentityProvider[origin={}; zone={}] - Alias ID and/or ZID changed during update of IdP with alias.",
                    getCleanedUserControlString(body.getOriginKey()),
                    getCleanedUserControlString(body.getIdentityZoneId())
            );
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }

        if (SAML.equals(body.getType())) {
            body.setOriginKey(existing.getOriginKey()); //we do not allow origin to change for a SAML provider, since that can cause clashes
            SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(body.getConfig(), SamlIdentityProviderDefinition.class);
            definition.setZoneId(zoneId);
            definition.setIdpEntityAlias(body.getOriginKey());
            samlConfigurator.validateSamlIdentityProviderDefinition(definition);
            body.setConfig(definition);
        }

        final IdentityProvider<?> updatedIdp;
        try {
            updatedIdp = transactionTemplate.execute(txStatus -> {
                final IdentityProvider<?> updatedOriginalIdp = identityProviderProvisioning.update(body, zoneId);
                return ensureConsistencyOfAliasIdp(updatedOriginalIdp, existing);
            });
        } catch (final IdpAliasFailedException e) {
            logger.warn("Could not create alias for {}", e.getMessage());
            final HttpStatus responseCode = Optional.ofNullable(HttpStatus.resolve(e.getHttpStatus())).orElse(INTERNAL_SERVER_ERROR);
            return new ResponseEntity<>(body, responseCode);
        }
        if (updatedIdp == null) {
            logger.warn(
                    "IdentityProvider[origin={}; zone={}] - Transaction updating IdP (and alias IdP, if applicable) was not successful, but no exception was thrown.",
                    getCleanedUserControlString(body.getOriginKey()),
                    getCleanedUserControlString(body.getIdentityZoneId())
            );
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        updatedIdp.setSerializeConfigRaw(rawConfig);
        redactSensitiveData(updatedIdp);

        return new ResponseEntity<>(updatedIdp, OK);
    }

    @RequestMapping (value = "{id}/status", method = PATCH)
    public ResponseEntity<IdentityProviderStatus> updateIdentityProviderStatus(@PathVariable String id, @RequestBody IdentityProviderStatus body) {
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        IdentityProvider existing = identityProviderProvisioning.retrieve(id, zoneId);
        if(body.getRequirePasswordChange() == null || !body.getRequirePasswordChange()) {
            logger.debug("Invalid payload. The property requirePasswordChangeRequired needs to be set");
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        if(!UAA.equals(existing.getType())) {
            logger.debug("Invalid operation. This operation is not supported on external IDP");
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        UaaIdentityProviderDefinition uaaIdentityProviderDefinition = ObjectUtils.castInstance(existing.getConfig(), UaaIdentityProviderDefinition.class);
        if(uaaIdentityProviderDefinition == null || uaaIdentityProviderDefinition.getPasswordPolicy() == null) {
            logger.debug("IDP does not have an existing PasswordPolicy. Operation not supported");
            return new ResponseEntity<>(body, UNPROCESSABLE_ENTITY);
        }
        uaaIdentityProviderDefinition.getPasswordPolicy().setPasswordNewerThan(new Date(System.currentTimeMillis()));
        identityProviderProvisioning.update(existing, zoneId);
        logger.info("PasswordChangeRequired property set for Identity Provider: " + existing.getId());

        /* since this operation is only allowed for IdPs of type "UAA" and aliases are not supported for "UAA" IdPs,
         * we do not need to propagate the changes to an alias IdP here. */

        logger.info("PasswordChangeRequired property set for Identity Provider: {}", existing.getId());
        return  new ResponseEntity<>(body, OK);
    }

    @RequestMapping(method = GET)
    public ResponseEntity<List<IdentityProvider>> retrieveIdentityProviders(@RequestParam(value = "active_only", required = false) String activeOnly, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        boolean retrieveActiveOnly = Boolean.parseBoolean(activeOnly);
        List<IdentityProvider> identityProviderList = identityProviderProvisioning.retrieveAll(retrieveActiveOnly, identityZoneManager.getCurrentIdentityZoneId());
        for(IdentityProvider idp : identityProviderList) {
            idp.setSerializeConfigRaw(rawConfig);
            redactSensitiveData(idp);
        }
        return new ResponseEntity<>(identityProviderList, OK);
    }

    @RequestMapping(value = "{id}", method = GET)
    public ResponseEntity<IdentityProvider> retrieveIdentityProvider(@PathVariable String id, @RequestParam(required = false, defaultValue = "false") boolean rawConfig) {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieve(id, identityZoneManager.getCurrentIdentityZoneId());
        identityProvider.setSerializeConfigRaw(rawConfig);
        redactSensitiveData(identityProvider);
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
            logger.error("Identity provider validation failed.", x);
            status = INTERNAL_SERVER_ERROR;
            exception = "check server logs";
        }finally {
            //destroy IDP
            manager.destroy();
        }
        //return results
        return new ResponseEntity<>(JsonUtils.writeValueAsString(exception), status);
    }

    private boolean aliasPropertiesAreValid(
            @NonNull final IdentityProvider<?> requestBody,
            @Nullable final IdentityProvider<?> existingIdp
    ) {
        // if the IdP already has an alias, the alias properties must not be changed
        final boolean idpAlreadyHasAlias = existingIdp != null && hasText(existingIdp.getAliasZid());
        if (idpAlreadyHasAlias) {
            if (!aliasEntitiesEnabled) {
                // if the feature is disabled, we only allow setting both alias properties to null
                return !hasText(requestBody.getAliasId()) && !hasText(requestBody.getAliasZid());
            }

            if (!hasText(existingIdp.getAliasId())) {
                // at this point, we expect both properties to be set -> if not, the IdP is in an inconsistent state
                throw new IllegalStateException(String.format(
                        "Both alias ID and alias ZID expected to be set for IdP '%s' in zone '%s'.",
                        existingIdp.getId(),
                        existingIdp.getIdentityZoneId()
                ));
            }

            // both alias properties must be equal in the update payload
            return existingIdp.getAliasId().equals(requestBody.getAliasId())
                    && existingIdp.getAliasZid().equals(requestBody.getAliasZid());
        }

        // if the IdP does not have an alias already, the aliasId must be empty
        if (hasText(requestBody.getAliasId())) {
            return false;
        }

        // check if the creation of an alias is necessary
        if (!hasText(requestBody.getAliasZid())) {
            return true;
        }

        /* At this point, we know that a new alias entity should be created.
         * -> check if the creation of alias entities is enabled */
        if (!aliasEntitiesEnabled) {
            return false;
        }

        // check if aliases are supported for this IdP type
        if (!IDP_TYPES_ALIAS_SUPPORTED.contains(requestBody.getType())) {
            return false;
        }

        // the referenced zone must exist
        try {
            identityZoneProvisioning.retrieve(requestBody.getAliasZid());
        } catch (final ZoneDoesNotExistsException e) {
            logger.debug(
                    "IdentityProvider[origin={}; zone={}] - Zone referenced in alias zone ID does not exist.",
                    requestBody.getOriginKey(),
                    requestBody.getIdentityZoneId()
            );
            return false;
        }

        // 'identityZoneId' and 'aliasZid' must not be equal
        if (requestBody.getIdentityZoneId().equals(requestBody.getAliasZid())) {
            return false;
        }

        // one of the zones must be 'uaa'
        return requestBody.getIdentityZoneId().equals(UAA) || requestBody.getAliasZid().equals(UAA);
    }

    /**
     * Ensure consistency during create or update operations with an alias IdP referenced in the original IdPs alias
     * properties. If the IdP has both its alias ID and alias ZID set, the existing alias IdP is updated. If only
     * the alias ZID is set, a new alias IdP is created.
     * This method should be executed in a transaction together with the original create or update operation. It is also
     * assumed that {@link IdentityProviderEndpoints#aliasPropertiesAreValid} returned {@code true} for the combination
     * of original IdP and existing IdP.
     *
     * @param originalIdp the original IdP; (changes to) it must already be persisted and its ID must therefore also be
     *                    present already
     * @param existingIdp the existing IdP before the update operation; for creation operations, this is {@code null}
     * @return the original IdP after the operation, with a potentially updated "aliasId" field
     * @throws IdpAliasFailedException if a new alias IdP needs to be created, but the zone referenced in 'aliasZid'
     *                                 does not exist
     * @throws IdpAliasFailedException if 'aliasId' and 'aliasZid' are set in the original IdP, but the referenced
     *                                 alias IdP could not be found
     */
    private <T extends AbstractIdentityProviderDefinition> IdentityProvider<?> ensureConsistencyOfAliasIdp(
            @NonNull final IdentityProvider<T> originalIdp,
            @Nullable final IdentityProvider<T> existingIdp
    ) throws IdpAliasFailedException {
        /* If the IdP had an alias before the update and the alias feature is now turned off, we break the reference
         * between the IdP and its alias by setting aliasId and aliasZid to null for both of them. Then, all other
         * changes are only applied to the original IdP. */
        final boolean idpHadAlias = existingIdp != null && hasText(existingIdp.getAliasZid());
        final boolean referenceBreakRequired = idpHadAlias && !aliasEntitiesEnabled;
        if (referenceBreakRequired) {
            if (!hasText(existingIdp.getAliasId())) {
                logger.warn(
                        "The state of the IdP [id={},zid={}] before the update had an aliasZid set, but no aliasId.",
                        existingIdp.getId(),
                        existingIdp.getIdentityZoneId()
                );
                return originalIdp;
            }

            final IdentityProvider<?> aliasIdp = retrieveAliasIdp(existingIdp);
            if (aliasIdp == null) {
                logger.warn(
                        "The referenced alias IdP [id='{}',zid='{}'] does not exist, therefore cannot break reference.",
                        existingIdp.getAliasId(),
                        existingIdp.getAliasZid()
                );
                return originalIdp;
            }

            aliasIdp.setAliasId(null);
            aliasIdp.setAliasZid(null);

            try {
                identityProviderProvisioning.update(aliasIdp, aliasIdp.getIdentityZoneId());
            } catch (final DataAccessException e) {
                throw new IdpAliasFailedException(existingIdp, COULD_NOT_BREAK_REFERENCE_TO_ALIAS, e);
            }

            // no change required in the original IdP since its aliasId and aliasZid were already set to null
            return originalIdp;
        }

        if (!hasText(originalIdp.getAliasZid())) {
            // no alias creation/update is necessary
            return originalIdp;
        }

        if (!aliasEntitiesEnabled) {
            /* Since we assume that the alias property validation was performed on the original IdP, both alias
             * properties should be set to null whenever the alias feature is disabled. */
            throw new IllegalStateException(String.format(
                    "The IdP [id='%s',zid='%s'] has non-empty aliasZid, even though alias entities are disabled.",
                    originalIdp.getId(),
                    originalIdp.getIdentityZoneId()
            ));
        }

        final IdentityProvider<T> aliasIdp = new IdentityProvider<>();
        aliasIdp.setActive(originalIdp.isActive());
        aliasIdp.setName(originalIdp.getName());
        aliasIdp.setOriginKey(originalIdp.getOriginKey());
        aliasIdp.setType(originalIdp.getType());
        aliasIdp.setConfig(originalIdp.getConfig());
        aliasIdp.setSerializeConfigRaw(originalIdp.isSerializeConfigRaw());
        // reference the ID and zone ID of the initial IdP entry
        aliasIdp.setAliasZid(originalIdp.getIdentityZoneId());
        aliasIdp.setAliasId(originalIdp.getId());
        aliasIdp.setIdentityZoneId(originalIdp.getAliasZid());

        // get the referenced alias IdP
        final IdentityProvider<?> existingAliasIdp;
        if (hasText(originalIdp.getAliasId())) {
            // if the referenced IdP does not exist, we create a new one
            existingAliasIdp = retrieveAliasIdp(originalIdp);
        } else {
            existingAliasIdp = null;
        }

        // update the existing alias IdP
        if (existingAliasIdp != null) {
            aliasIdp.setId(existingAliasIdp.getId());
            identityProviderProvisioning.update(aliasIdp, originalIdp.getAliasZid());
            return originalIdp;
        }

        final IdentityProvider<?> persistedAliasIdp = createNewAliasIdp(aliasIdp, originalIdp.getAliasZid());

        // update alias ID in original IdP
        originalIdp.setAliasId(persistedAliasIdp.getId());
        return identityProviderProvisioning.update(originalIdp, originalIdp.getIdentityZoneId());
    }

    /**
     * Persist the given alias IdP in the given zone.
     *
     * @param aliasIdp the alias IdP to persist
     * @param aliasZid the ID of the identity zone in which the alias should be persisted
     * @return the persisted alias IdP
     */
    private <T extends AbstractIdentityProviderDefinition> IdentityProvider<?> createNewAliasIdp(
            final IdentityProvider<T> aliasIdp,
            final String aliasZid
    ) throws IdpAliasFailedException {
        // check if IdZ referenced in 'aliasZid' exists
        try {
            identityZoneProvisioning.retrieve(aliasZid);
        } catch (final ZoneDoesNotExistsException e) {
            throw new IdpAliasFailedException(aliasIdp.getAliasId(), aliasIdp.getAliasZid(), null, aliasZid, ALIAS_ZONE_DOES_NOT_EXIST, e);
        }

        // create new alias IdP in alias zid
        final IdentityProvider<?> persistedAliasIdp;
        try {
            persistedAliasIdp = identityProviderProvisioning.create(
                    aliasIdp,
                    aliasZid
            );
        } catch (final IdpAlreadyExistsException e) {
            throw new IdpAliasFailedException(aliasIdp.getAliasId(), aliasIdp.getAliasZid(), null, aliasZid, ORIGIN_KEY_ALREADY_USED_IN_ALIAS_ZONE, e);
        }

        return persistedAliasIdp;
    }

    @Nullable
    private IdentityProvider<?> retrieveAliasIdp(final IdentityProvider<?> idp) {
        try {
            return identityProviderProvisioning.retrieve(idp.getAliasId(), idp.getAliasZid());
        } catch (final EmptyResultDataAccessException e) {
            logger.warn(
                    "The IdP referenced in the 'aliasId' ('{}') and 'aliasZid' ('{}') of the IdP '{}' does not exist.",
                    idp.getAliasId(),
                    idp.getAliasZid(),
                    idp.getId()
            );
            return null;
        }
    }

//    @ExceptionHandler(MetadataProviderException.class)
//    public ResponseEntity<String> handleMetadataProviderException(MetadataProviderException e) {
//        if (e.getMessage().contains("Duplicate")) {
//            return new ResponseEntity<>(e.getMessage(), CONFLICT);
//        } else {
//            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
//        }
//    }

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
                if (provider.getConfig() instanceof LdapIdentityProviderDefinition) {
                    LdapIdentityProviderDefinition definition = (LdapIdentityProviderDefinition) provider.getConfig();
                    if (definition.getBindPassword() == null) {
                        IdentityProvider existing = identityProviderProvisioning.retrieve(id, zoneId);
                        if (existing!=null &&
                            existing.getConfig()!=null &&
                            existing.getConfig() instanceof LdapIdentityProviderDefinition) {
                            LdapIdentityProviderDefinition existingDefinition = (LdapIdentityProviderDefinition)existing.getConfig();
                            definition.setBindPassword(existingDefinition.getBindPassword());
                        }
                    }
                }
                break;
            }
            case OAUTH20 :
            case OIDC10 : {
                if (provider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition) {
                    AbstractExternalOAuthIdentityProviderDefinition definition = (AbstractExternalOAuthIdentityProviderDefinition) provider.getConfig();
                    if (definition.getRelyingPartySecret() == null) {
                        IdentityProvider existing = identityProviderProvisioning.retrieve(id, zoneId);
                        if (existing!=null &&
                            existing.getConfig()!=null &&
                            existing.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition) {
                            AbstractExternalOAuthIdentityProviderDefinition existingDefinition = (AbstractExternalOAuthIdentityProviderDefinition)existing.getConfig();
                            definition.setRelyingPartySecret(existingDefinition.getRelyingPartySecret());
                        }
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
                if (provider.getConfig() instanceof LdapIdentityProviderDefinition) {
                    logger.debug("Removing bind password from LDAP provider id:"+provider.getId());
                    LdapIdentityProviderDefinition definition = (LdapIdentityProviderDefinition) provider.getConfig();
                    definition.setBindPassword(null);
                }
                break;
            }
            case OAUTH20 :
            case OIDC10 : {
                if (provider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition) {
                    logger.debug("Removing relying secret from OAuth/OIDC provider id:"+provider.getId());
                    AbstractExternalOAuthIdentityProviderDefinition definition = (AbstractExternalOAuthIdentityProviderDefinition) provider.getConfig();
                    definition.setRelyingPartySecret(null);
                }
                break;
            }
            default:
                break;

        }
    }

}
