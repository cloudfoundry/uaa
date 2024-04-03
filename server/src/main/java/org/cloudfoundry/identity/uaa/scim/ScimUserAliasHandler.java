package org.cloudfoundry.identity.uaa.scim;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class ScimUserAliasHandler extends EntityAliasHandler<ScimUser> {
    private final ScimUserProvisioning scimUserProvisioning;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final IdentityZoneManager identityZoneManager;

    protected ScimUserAliasHandler(
            @Qualifier("identityZoneProvisioning") final IdentityZoneProvisioning identityZoneProvisioning,
            final ScimUserProvisioning scimUserProvisioning,
            final IdentityProviderProvisioning identityProviderProvisioning,
            final IdentityZoneManager identityZoneManager,
            @Value("${login.aliasEntitiesEnabled:false}") final boolean aliasEntitiesEnabled
    ) {
        super(identityZoneProvisioning, aliasEntitiesEnabled);
        this.scimUserProvisioning = scimUserProvisioning;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    protected boolean additionalValidationChecksForNewAlias(final ScimUser requestBody) {
        /* check if an IdP with the user's origin exists in both the current and the alias zone and that they are
         * aliases of each other */
        final String origin = requestBody.getOrigin();
        final IdentityProvider<?> idpInAliasZone = retrieveIdpByOrigin(origin, requestBody.getAliasZid());
        final IdentityProvider<?> idpInCurrentZone = retrieveIdpByOrigin(origin, identityZoneManager.getCurrentIdentityZoneId());
        return EntityAliasHandler.isValidAliasPair(idpInCurrentZone, idpInAliasZone);
    }

    private IdentityProvider<?> retrieveIdpByOrigin(final String originKey, final String zoneId) {
        final IdentityProvider<?> idpInAliasZone;
        try {
            idpInAliasZone = identityProviderProvisioning.retrieveByOrigin(originKey, zoneId);
        } catch (final EmptyResultDataAccessException e) {
            throw new ScimException(
                    String.format("No IdP with the origin '%s' exists in the zone '%s'.", originKey, zoneId),
                    HttpStatus.BAD_REQUEST
            );
        }
        return idpInAliasZone;
    }

    @Override
    protected void setId(final ScimUser entity, final String id) {
        entity.setId(id);
    }

    @Override
    protected void setZoneId(final ScimUser entity, final String zoneId) {
        entity.setZoneId(zoneId);
    }

    @Override
    protected ScimUser cloneEntity(final ScimUser originalEntity) {
        final ScimUser aliasUser = new ScimUser();

        aliasUser.setUserName(originalEntity.getUserName());
        aliasUser.setUserType(originalEntity.getUserType());

        aliasUser.setOrigin(originalEntity.getOrigin());
        aliasUser.setExternalId(originalEntity.getExternalId());

        aliasUser.setTitle(originalEntity.getTitle());
        aliasUser.setName(originalEntity.getName());
        aliasUser.setDisplayName(originalEntity.getDisplayName());
        aliasUser.setNickName(originalEntity.getNickName());

        aliasUser.setEmails(originalEntity.getEmails());
        aliasUser.setPhoneNumbers(originalEntity.getPhoneNumbers());

        aliasUser.setLocale(originalEntity.getLocale());
        aliasUser.setTimezone(originalEntity.getTimezone());
        aliasUser.setProfileUrl(originalEntity.getProfileUrl());

        final String passwordOriginalEntity = scimUserProvisioning.retrievePasswordForUser(
                originalEntity.getId(),
                originalEntity.getZoneId()
        );
        aliasUser.setPassword(passwordOriginalEntity);
        aliasUser.setSalt(originalEntity.getSalt());
        aliasUser.setPasswordLastModified(originalEntity.getPasswordLastModified());
        aliasUser.setLastLogonTime(originalEntity.getLastLogonTime());

        aliasUser.setActive(originalEntity.isActive());
        aliasUser.setVerified(originalEntity.isVerified());

        // the alias user won't have any groups or approvals in the alias zone, they need to be assigned separately
        aliasUser.setApprovals(emptySet());
        aliasUser.setGroups(emptyList());

        aliasUser.setSchemas(originalEntity.getSchemas());

        // aliasId, aliasZid, id and zoneId are set in the parent class

        return aliasUser;
    }

    @Override
    protected Optional<ScimUser> retrieveEntity(final String id, final String zoneId) {
        final ScimUser user;
        try {
            user = scimUserProvisioning.retrieve(id, zoneId);
        } catch (final ScimResourceNotFoundException e) {
            return Optional.empty();
        }
        return Optional.ofNullable(user);
    }

    @Override
    protected ScimUser updateEntity(final ScimUser entity, final String zoneId) {
        return scimUserProvisioning.update(entity.getId(), entity, zoneId);
    }

    @Override
    protected ScimUser createEntity(final ScimUser entity, final String zoneId) {
        try {
            return scimUserProvisioning.createUser(entity, entity.getPassword(), zoneId);
        } catch (final ScimResourceAlreadyExistsException e) {
            final String errorMessage = String.format(
                    "Could not create %s. A user with the same username already exists in the alias zone.",
                    entity.getAliasDescription()
            );
            throw new EntityAliasFailedException(errorMessage, HttpStatus.CONFLICT.value(), e);
        }
    }
}
