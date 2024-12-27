package org.cloudfoundry.identity.uaa.provider;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;

import java.util.Optional;
import java.util.Set;

import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

@Component
public class IdentityProviderAliasHandler extends EntityAliasHandler<IdentityProvider<?>> {
    private static final Logger LOGGER = LoggerFactory.getLogger(IdentityProviderAliasHandler.class);

    /**
     * The IdP types for which alias IdPs (via 'aliasId' and 'aliasZid') are supported.
     */
    public static final Set<String> IDP_TYPES_ALIAS_SUPPORTED = Set.of(SAML, OAUTH20, OIDC10);

    private final IdentityProviderProvisioning identityProviderProvisioning;

    public IdentityProviderAliasHandler(
            @Qualifier("identityZoneProvisioning") final IdentityZoneProvisioning identityZoneProvisioning,
            final IdentityProviderProvisioning identityProviderProvisioning,
            @Qualifier("aliasEntitiesEnabled") final boolean aliasEntitiesEnabled
    ) {
        super(identityZoneProvisioning, aliasEntitiesEnabled);
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    @Override
    protected boolean additionalValidationChecksForNewAlias(@NonNull final IdentityProvider<?> requestBody) {
        // check if aliases are supported for this IdP type
        return IDP_TYPES_ALIAS_SUPPORTED.contains(requestBody.getType());
    }

    @Override
    protected void setPropertiesFromExistingAliasEntity(
            final IdentityProvider<?> newAliasEntity,
            final IdentityProvider<?> existingAliasEntity
    ) {
        // not required for identity providers
    }

    @Override
    protected void setId(final IdentityProvider<?> entity, final String id) {
        entity.setId(id);
    }

    @Override
    protected void setZoneId(final IdentityProvider<?> entity, final String zoneId) {
        entity.setIdentityZoneId(zoneId);
    }

    @Override
    protected IdentityProvider<?> cloneEntity(final IdentityProvider<?> originalEntity) {
        final IdentityProvider clonedIdp = new IdentityProvider<>();
        clonedIdp.setActive(originalEntity.isActive());
        clonedIdp.setName(originalEntity.getName());
        clonedIdp.setOriginKey(originalEntity.getOriginKey());
        clonedIdp.setType(originalEntity.getType());
        clonedIdp.setConfig(originalEntity.getConfig());
        clonedIdp.setSerializeConfigRaw(originalEntity.isSerializeConfigRaw());
        return clonedIdp;
    }

    @Override
    protected Optional<IdentityProvider<?>> retrieveEntity(final String id, final String zoneId) {
        final IdentityProvider<?> identityProvider;
        try {
            identityProvider = identityProviderProvisioning.retrieve(id, zoneId);
        } catch (final EmptyResultDataAccessException e) {
            LOGGER.warn("The IdP with ID '{}' does not exist in the zone '{}'.", id, zoneId);
            return Optional.empty();
        }
        return Optional.ofNullable(identityProvider);
    }

    @Override
    protected IdentityProvider<?> updateEntity(final IdentityProvider<?> entity, final String zoneId) {
        return identityProviderProvisioning.update(entity, zoneId);
    }

    @Override
    protected IdentityProvider<?> createEntity(final IdentityProvider<?> entity, final String zoneId) {
        try {
            return identityProviderProvisioning.create(entity, zoneId);
        } catch (final IdpAlreadyExistsException e) {
            final String errorMessage = "Could not create %s. An IdP with this origin already exists in the alias zone.".formatted(
                    entity.getAliasDescription()
            );
            throw new EntityAliasFailedException(errorMessage, HttpStatus.CONFLICT.value(), e);
        }
    }
}
