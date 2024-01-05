package org.cloudfoundry.identity.uaa.scim;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.EntityMirroringHandler;
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
public class ScimUserMirroringHandler extends EntityMirroringHandler<ScimUser> {
    private final ScimUserProvisioning scimUserProvisioning;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final IdentityZoneManager identityZoneManager;

    protected ScimUserMirroringHandler(
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
    protected boolean additionalValidationChecksForNewMirroring(final ScimUser requestBody) {
        // check if the IdP also exists as a mirrored IdP in the alias zone
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
        return EntityMirroringHandler.isCorrectlyMirroredPair(idpInCurrentZone, idpInAliasZone);
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
        final ScimUser mirroredUser = new ScimUser();

        mirroredUser.setTitle(originalEntity.getTitle());
        mirroredUser.setDisplayName(originalEntity.getDisplayName());
        mirroredUser.setName(originalEntity.getName());
        mirroredUser.setNickName(originalEntity.getNickName());
        mirroredUser.setPhoneNumbers(originalEntity.getPhoneNumbers());
        mirroredUser.setEmails(originalEntity.getEmails());
        mirroredUser.setPrimaryEmail(originalEntity.getPrimaryEmail());
        mirroredUser.setLocale(originalEntity.getLocale());
        mirroredUser.setTimezone(originalEntity.getTimezone());
        mirroredUser.setProfileUrl(originalEntity.getProfileUrl());

        mirroredUser.setPassword(originalEntity.getPassword());
        mirroredUser.setSalt(originalEntity.getSalt());
        mirroredUser.setPasswordLastModified(originalEntity.getPasswordLastModified());
        mirroredUser.setLastLogonTime(originalEntity.getLastLogonTime());

        mirroredUser.setActive(originalEntity.isActive());
        mirroredUser.setVerified(originalEntity.isVerified());

        mirroredUser.setApprovals(originalEntity.getApprovals());
        mirroredUser.setGroups(originalEntity.getGroups());

        mirroredUser.setOrigin(originalEntity.getOrigin());
        mirroredUser.setExternalId(originalEntity.getExternalId());
        mirroredUser.setUserType(originalEntity.getUserType());

        mirroredUser.setMeta(originalEntity.getMeta());
        mirroredUser.setSchemas(originalEntity.getSchemas());

        // aliasId, aliasZid, id and zoneId are set in the parent class

        return mirroredUser;
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
