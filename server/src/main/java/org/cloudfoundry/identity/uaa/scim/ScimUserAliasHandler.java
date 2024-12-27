package org.cloudfoundry.identity.uaa.scim;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.EMPTY_STRING;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class ScimUserAliasHandler extends EntityAliasHandler<ScimUser> {
    private final ScimUserProvisioning scimUserProvisioning;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final IdentityZoneManager identityZoneManager;

    public ScimUserAliasHandler(
            @Qualifier("identityZoneProvisioning") final IdentityZoneProvisioning identityZoneProvisioning,
            final ScimUserProvisioning scimUserProvisioning,
            final IdentityProviderProvisioning identityProviderProvisioning,
            final IdentityZoneManager identityZoneManager,
            @Qualifier("aliasEntitiesEnabled") final boolean aliasEntitiesEnabled
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
        final Optional<IdentityProvider<?>> idpInAliasZone = retrieveIdpByOrigin(origin, requestBody.getAliasZid());
        if (idpInAliasZone.isEmpty()) {
            return false;
        }
        final Optional<IdentityProvider<?>> idpInCurrentZone = retrieveIdpByOrigin(origin, identityZoneManager.getCurrentIdentityZoneId());
        if (idpInCurrentZone.isEmpty()) {
            return false;
        }
        return EntityAliasHandler.isValidAliasPair(idpInCurrentZone.get(), idpInAliasZone.get());
    }

    @Override
    protected void setPropertiesFromExistingAliasEntity(
            final ScimUser newAliasEntity,
            final ScimUser existingAliasEntity
    ) {
        // these three timestamps should not be overwritten by the timestamps of the original user
        newAliasEntity.setPasswordLastModified(existingAliasEntity.getPasswordLastModified());
        newAliasEntity.setLastLogonTime(existingAliasEntity.getLastLogonTime());
        newAliasEntity.setPreviousLogonTime(existingAliasEntity.getPreviousLogonTime());

        // the version field might differ between the original user and its alias -> use value of existing alias
        newAliasEntity.setVersion(existingAliasEntity.getVersion());
    }

    private Optional<IdentityProvider<?>> retrieveIdpByOrigin(final String originKey, final String zoneId) {
        final IdentityProvider<?> idpInAliasZone;
        try {
            idpInAliasZone = identityProviderProvisioning.retrieveByOrigin(originKey, zoneId);
        } catch (final EmptyResultDataAccessException e) {
            return Optional.empty();
        }
        return Optional.ofNullable(idpInAliasZone);
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

        aliasUser.setExternalId(originalEntity.getExternalId());

        /* we only allow alias users to be created if their origin IdP has an alias to the same zone, therefore, an IdP
         * with the same origin key will exist in the alias zone  */
        aliasUser.setOrigin(originalEntity.getOrigin());

        aliasUser.setUserName(originalEntity.getUserName());
        aliasUser.setName(new ScimUser.Name(originalEntity.getGivenName(), originalEntity.getFamilyName()));

        aliasUser.setEmails(originalEntity.getEmails());
        aliasUser.setPhoneNumbers(originalEntity.getPhoneNumbers());

        aliasUser.setActive(originalEntity.isActive());
        aliasUser.setVerified(originalEntity.isVerified());

        /* password: empty string
         *  - alias users are only allowed for IdPs that also have an alias
         *  - IdPs can only have an alias if they are of type SAML, OIDC or OAuth 2.0
         *  - users with such IdPs as their origin always have an empty password
         */
        aliasUser.setPassword(EMPTY_STRING);
        aliasUser.setSalt(null);

        /* The following fields will be overwritten later and are therefore not set here:
         * - id and identityZoneId
         * - aliasId and aliasZid
         * - timestamp fields (password last modified, last logon, previous logon):
         *      - creation: with current timestamp during persistence (JdbcScimUserProvisioning)
         *      - update: with values from existing alias entity
         */

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
            final String errorMessage = "Could not create %s. A user with the same username already exists in the alias zone.".formatted(
                    entity.getAliasDescription()
            );
            throw new EntityAliasFailedException(errorMessage, HttpStatus.CONFLICT.value(), e);
        }
    }
}
