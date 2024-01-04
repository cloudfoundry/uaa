package org.cloudfoundry.identity.uaa.provider;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.EntityMirroringHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Component;

@Component
public class IdentityProviderMirroringHandler extends EntityMirroringHandler<IdentityProvider<?>> {
    private static final Logger LOGGER = LoggerFactory.getLogger(IdentityProviderMirroringHandler.class);
    private final IdentityProviderProvisioning identityProviderProvisioning;

    protected IdentityProviderMirroringHandler(
            @Qualifier("identityZoneProvisioning") final IdentityZoneProvisioning identityZoneProvisioning,
            final IdentityProviderProvisioning identityProviderProvisioning
    ) {
        super(identityZoneProvisioning);
        this.identityProviderProvisioning = identityProviderProvisioning;
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
        final IdentityProvider mirroredIdp = new IdentityProvider<>();
        mirroredIdp.setActive(originalEntity.isActive());
        mirroredIdp.setName(originalEntity.getName());
        mirroredIdp.setOriginKey(originalEntity.getOriginKey());
        mirroredIdp.setType(originalEntity.getType());
        mirroredIdp.setConfig(originalEntity.getConfig());
        mirroredIdp.setSerializeConfigRaw(originalEntity.isSerializeConfigRaw());
        // reference the ID and zone ID of the initial IdP entry
        mirroredIdp.setAliasZid(originalEntity.getIdentityZoneId());
        mirroredIdp.setAliasId(originalEntity.getId());
        mirroredIdp.setIdentityZoneId(originalEntity.getAliasZid());
        return mirroredIdp;
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
        return identityProviderProvisioning.create(entity, zoneId);
    }
}
