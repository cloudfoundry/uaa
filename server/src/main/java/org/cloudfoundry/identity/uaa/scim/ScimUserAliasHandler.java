package org.cloudfoundry.identity.uaa.scim;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
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
            final IdentityZoneManager identityZoneManager
    ) {
        super(identityZoneProvisioning);
        this.scimUserProvisioning = scimUserProvisioning;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    protected boolean additionalValidationChecksForNewAlias(final ScimUser requestBody) {
        // check if the IdP also exists as an alias IdP in the alias zone
        final IdentityProvider<?> idpInAliasZone;
        try {
            idpInAliasZone = identityProviderProvisioning.retrieveByOrigin(
                    requestBody.getOrigin(),
                    requestBody.getAliasZid()
            );
        } catch (final DataAccessException e) {
            throw new ScimException(
                    String.format("No IdP with the origin '%s' exists in the alias zone.", requestBody.getOrigin()),
                    HttpStatus.BAD_REQUEST
            );
        }

        final IdentityProvider<?> idpInCurrentZone = identityProviderProvisioning.retrieveByOrigin(
                requestBody.getOrigin(),
                identityZoneManager.getCurrentIdentityZoneId()
        );
        return EntityAliasHandler.isCorrectAliasPair(idpInCurrentZone, idpInAliasZone);
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

        aliasUser.setTitle(originalEntity.getTitle());
        aliasUser.setDisplayName(originalEntity.getDisplayName());
        aliasUser.setName(originalEntity.getName());
        aliasUser.setNickName(originalEntity.getNickName());
        aliasUser.setPhoneNumbers(originalEntity.getPhoneNumbers());
        aliasUser.setEmails(originalEntity.getEmails());
        aliasUser.setPrimaryEmail(originalEntity.getPrimaryEmail());
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
        aliasUser.setGroups(originalEntity.getGroups());

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
        return scimUserProvisioning.create(entity, zoneId);
    }
}
