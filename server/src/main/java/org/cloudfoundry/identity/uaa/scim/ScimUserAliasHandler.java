package org.cloudfoundry.identity.uaa.scim;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.alias.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
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
        final IdentityProvider<?> idpInAliasZone = retrieveIdpByOrigin(
                requestBody.getOrigin(),
                requestBody.getAliasZid()
        );
        final IdentityProvider<?> idpInCurrentZone = retrieveIdpByOrigin(
                requestBody.getOrigin(),
                identityZoneManager.getCurrentIdentityZoneId()
        );
        return EntityAliasHandler.isValidAliasPair(idpInCurrentZone, idpInAliasZone);
    }

    private IdentityProvider<?> retrieveIdpByOrigin(final String originKey, final String zoneId) {
        final IdentityProvider<?> idpInAliasZone;
        try {
            idpInAliasZone = identityProviderProvisioning.retrieveByOrigin(
                    originKey,
                    zoneId
            );
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

        aliasUser.setName(originalEntity.getName());
        aliasUser.setDisplayName(originalEntity.getDisplayName());
        aliasUser.setNickName(originalEntity.getNickName());
        aliasUser.setUserName(originalEntity.getUserName());

        aliasUser.setEmails(originalEntity.getEmails());
        aliasUser.setPrimaryEmail(originalEntity.getPrimaryEmail());
        aliasUser.setPhoneNumbers(originalEntity.getPhoneNumbers());

        aliasUser.setTitle(originalEntity.getTitle());
        aliasUser.setLocale(originalEntity.getLocale());
        aliasUser.setTimezone(originalEntity.getTimezone());
        aliasUser.setProfileUrl(originalEntity.getProfileUrl());

        aliasUser.setPassword(originalEntity.getPassword());
        aliasUser.setSalt(originalEntity.getSalt());
        aliasUser.setPasswordLastModified(originalEntity.getPasswordLastModified());
        aliasUser.setLastLogonTime(originalEntity.getLastLogonTime());

        aliasUser.setActive(originalEntity.isActive());
        aliasUser.setVerified(originalEntity.isVerified());

        aliasUser.setApprovals(originalEntity.getApprovals());
        if (originalEntity.getGroups() != null) {
            aliasUser.setGroups(originalEntity.getGroups());
        }

        aliasUser.setOrigin(originalEntity.getOrigin());
        aliasUser.setExternalId(originalEntity.getExternalId());
        aliasUser.setUserType(originalEntity.getUserType());

        aliasUser.setMeta(originalEntity.getMeta());
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
        return scimUserProvisioning.createUser(entity, entity.getPassword(), zoneId);
    }
}
