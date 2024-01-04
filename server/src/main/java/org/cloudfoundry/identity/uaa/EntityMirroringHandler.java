package org.cloudfoundry.identity.uaa;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.springframework.util.StringUtils.hasText;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.provider.IdpMirroringFailedException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

public abstract class EntityMirroringHandler<T extends MirroredEntity> {
    private static final Logger LOGGER = LoggerFactory.getLogger(EntityMirroringHandler.class);

    private final IdentityZoneProvisioning identityZoneProvisioning;

    protected EntityMirroringHandler(final IdentityZoneProvisioning identityZoneProvisioning) {
        this.identityZoneProvisioning = identityZoneProvisioning;
    }

    public boolean aliasPropertiesAreValid(
            @NonNull final T requestBody,
            @Nullable final T existingEntity
    ) {
        final boolean entityWasAlreadyMirrored = existingEntity != null && hasText(existingEntity.getAliasZid());

        if (entityWasAlreadyMirrored) {
            if (!hasText(existingEntity.getAliasId())) {
                // at this point, we expect both properties to be set -> if not, the entity is in an inconsistent state
                throw new IllegalStateException(String.format(
                        "Both alias ID and alias ZID expected to be set for existing entity of type '%s' with ID '%s' in zone '%s'.",
                        existingEntity.getClass().getSimpleName(),
                        existingEntity.getId(),
                        existingEntity.getZoneId()
                ));
            }

            // both properties must be left unchanged in the operation
            return existingEntity.getAliasId().equals(requestBody.getAliasId())
                    && existingEntity.getAliasZid().equals(requestBody.getAliasId());
        }

        // alias ID must not be set when a new mirroring is to be set up
        if (hasText(requestBody.getAliasId())) {
            return false;
        }

        // check if mirroring is necessary
        if (!hasText(requestBody.getAliasZid())) {
            return true;
        }

        // the referenced zone must exist
        try {
            identityZoneProvisioning.retrieve(requestBody.getAliasZid());
        } catch (final ZoneDoesNotExistsException e) {
            LOGGER.debug("Zone referenced in alias zone ID does not exist.");
            return false;
        }

        // 'identityZoneId' and 'aliasZid' must not be equal
        if (requestBody.getZoneId().equals(requestBody.getAliasZid())) {
            return false;
        }

        // one of the zones must be 'uaa'
        return requestBody.getZoneId().equals(UAA) || requestBody.getAliasZid().equals(UAA);
    }

    // TODO validate method expected to be true
    // TODO comment: original entity must already be created, i.e., have an ID
    // TODO must be executed in a transaction with the original creation/update
    public T ensureConsistencyOfMirroredEntity(final T originalEntity) {
        if (!hasText(originalEntity.getAliasZid())) {
            // no mirroring is necessary
            return originalEntity;
        }

        final T mirroredEntity = buildMirroredEntity(originalEntity);

        // get the existing mirrored entity, if present
        final T existingMirroredEntity;
        if (hasText(originalEntity.getAliasId())) {
            // if the referenced mirrored entity cannot be retrieved, we create a new one later
            existingMirroredEntity = retrieveMirroredEntity(originalEntity).orElse(null);
        } else {
            existingMirroredEntity = null;
        }

        // update the existing mirrored entity
        if (existingMirroredEntity != null) {
            setId(mirroredEntity, existingMirroredEntity.getId());
            updateEntity(mirroredEntity, originalEntity.getAliasZid());
            return originalEntity;
        }

        // check if IdZ referenced in 'aliasZid' exists
        try {
            identityZoneProvisioning.retrieve(originalEntity.getAliasZid());
        } catch (final ZoneDoesNotExistsException e) {
            throw new IdpMirroringFailedException(String.format(
                    "Could not mirror user '%s' to zone '%s', as zone does not exist.",
                    originalEntity.getId(),
                    originalEntity.getAliasZid()
            ), e);
        }

        // create new mirrored entity in alias zid
        final T persistedMirroredEntity = createEntity(mirroredEntity, originalEntity.getAliasZid());

        // update alias ID in original entity
        setId(originalEntity, persistedMirroredEntity.getId());
        return updateEntity(originalEntity, originalEntity.getZoneId());
    }

    protected abstract void setId(final T entity, final String newId);

    protected abstract T buildMirroredEntity(final T originalEntity);

    private Optional<T> retrieveMirroredEntity(final T originalEntity) {
        return retrieveEntity(originalEntity.getAliasId(), originalEntity.getAliasZid());
    }

    protected abstract Optional<T> retrieveEntity(final String id, final String zoneId);

    protected abstract T updateEntity(final T entity, final String zoneId);

    protected abstract T createEntity(final T entity, final String zoneId);
}
