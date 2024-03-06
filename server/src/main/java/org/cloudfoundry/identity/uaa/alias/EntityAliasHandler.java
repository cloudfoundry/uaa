package org.cloudfoundry.identity.uaa.alias;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.springframework.util.StringUtils.hasText;

import java.util.Optional;

import org.cloudfoundry.identity.uaa.EntityWithAlias;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

public abstract class EntityAliasHandler<T extends EntityWithAlias> {
    private static final Logger LOGGER = LoggerFactory.getLogger(EntityAliasHandler.class);

    private final IdentityZoneProvisioning identityZoneProvisioning;
    private final boolean aliasEntitiesEnabled;

    protected EntityAliasHandler(
            final IdentityZoneProvisioning identityZoneProvisioning,
            final boolean aliasEntitiesEnabled
    ) {
        this.identityZoneProvisioning = identityZoneProvisioning;
        this.aliasEntitiesEnabled = aliasEntitiesEnabled;
    }

    public final boolean aliasPropertiesAreValid(
            @NonNull final T requestBody,
            @Nullable final T existingEntity
    ) {
        // if the entity already has an alias, the alias properties must not be changed
        final boolean entityAlreadyHasAlias = existingEntity != null && hasText(existingEntity.getAliasZid());
        if (entityAlreadyHasAlias) {
            if (!aliasEntitiesEnabled) {
                // if the feature is disabled, we only allow setting both alias properties to null
                return !hasText(requestBody.getAliasId()) && !hasText(requestBody.getAliasZid());
            }

            if (!hasText(existingEntity.getAliasId())) {
                // at this point, we expect both properties to be set -> if not, the entity is in an inconsistent state
                throw new IllegalStateException(String.format(
                        "Both alias ID and alias ZID expected to be set for existing entity %s.",
                        existingEntity.getAliasDescription()
                ));
            }

            // both properties must be left unchanged in the operation
            return existingEntity.getAliasId().equals(requestBody.getAliasId())
                    && existingEntity.getAliasZid().equals(requestBody.getAliasZid());
        }

        // alias ID must not be set when no alias existed already
        if (hasText(requestBody.getAliasId())) {
            return false;
        }

        // exit early if no alias creation is necessary
        if (!hasText(requestBody.getAliasZid())) {
            return true;
        }

        /* At this point, we know that a new alias entity should be created.
         * -> check if the creation of alias entities is enabled */
        if (!aliasEntitiesEnabled) {
            return false;
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
        final boolean oneOfTheZonesIsUaaZone = requestBody.getZoneId().equals(UAA)
                || requestBody.getAliasZid().equals(UAA);
        if (!oneOfTheZonesIsUaaZone) {
            return false;
        }

        // perform additional checks
        return additionalValidationChecksForNewAlias(requestBody);
    }

    /**
     * Perform additional validation checks specific for the entity. This method is only executed if a new alias
     * entity is created in the alias zone.
     */
    protected abstract boolean additionalValidationChecksForNewAlias(@NonNull final T requestBody);

    /**
     * Ensure consistency during create or update operations with an alias entity referenced in the original entity's
     * alias properties. If the entity has both its alias ID and alias ZID set, the existing alias entity is updated.
     * If only the alias ZID is set, a new alias entity is created.
     * This method should be executed in a transaction together with the original create or update operation. Before
     * executing this method, check if the alias properties are valid by calling
     * {@link EntityAliasHandler#aliasPropertiesAreValid(EntityWithAlias, EntityWithAlias)}.
     * The original entity or the update to it must be persisted prior to calling this method, as we expect that its ID
     * is already set.
     *
     * @param originalEntity the original entity
     * @return the original entity after the operation
     * @throws EntityAliasFailedException if a new alias entity needs to be created, but the zone referenced in
     *                                    'aliasZid' does not exist
     * @throws EntityAliasFailedException if 'aliasId' and 'aliasZid' are set in the original entity, but the
     *                                    referenced alias entity could not be found
     */
    public final T ensureConsistencyOfAliasEntity(
            @NonNull final T originalEntity,
            @Nullable final T existingEntity
    ) throws EntityAliasFailedException {
        /* If the entity had an alias before the update and the alias feature is now turned off, we break the reference
         * between the entity and its alias by setting aliasId and aliasZid to null for both of them. Then, all other
         * changes are only applied to the original entity. */
        final boolean entityHadAlias = existingEntity != null && hasText(existingEntity.getAliasZid());
        final boolean referenceBreakRequired = entityHadAlias && !aliasEntitiesEnabled;
        if (referenceBreakRequired) {
            if (!hasText(existingEntity.getAliasId())) {
                LOGGER.warn(
                        "The state of the entity {} before the update had an aliasZid set, but no aliasId.",
                        existingEntity.getAliasDescription()
                );
                return originalEntity;
            }

            final Optional<T> aliasEntityOpt = retrieveAliasEntity(existingEntity);
            if (aliasEntityOpt.isEmpty()) {
                LOGGER.warn(
                        "The alias referenced in entity {} does not exist, therefore cannot break reference.",
                        existingEntity.getAliasDescription()
                );
                return originalEntity;
            }

            final T aliasEntity = aliasEntityOpt.get();
            aliasEntity.setAliasId(null);
            aliasEntity.setAliasZid(null);

            try {
                updateEntity(aliasEntity, aliasEntity.getZoneId());
            } catch (final DataAccessException e) {
                throw new EntityAliasFailedException(
                        String.format(
                                "Could not break reference to alias in entity %s.",
                                existingEntity.getAliasDescription()
                        ), HttpStatus.UNPROCESSABLE_ENTITY.value(), e
                );
            }

            // no change required in the original entity since its aliasId and aliasZid were already set to null
            return originalEntity;
        }

        if (!hasText(originalEntity.getAliasZid())) {
            // no alias handling is necessary
            return originalEntity;
        }

        final T aliasEntity = buildAliasEntity(originalEntity);

        // get the existing alias entity, if present
        final T existingAliasEntity;
        if (hasText(originalEntity.getAliasId())) {
            // if the referenced alias entity cannot be retrieved, we create a new one later
            existingAliasEntity = retrieveAliasEntity(originalEntity).orElse(null);
        } else {
            existingAliasEntity = null;
        }

        // update the existing alias entity
        if (existingAliasEntity != null) {
            setId(aliasEntity, existingAliasEntity.getId());
            updateEntity(aliasEntity, originalEntity.getAliasZid());
            return originalEntity;
        }

        // check if IdZ referenced in 'aliasZid' exists
        try {
            identityZoneProvisioning.retrieve(originalEntity.getAliasZid());
        } catch (final ZoneDoesNotExistsException e) {
            final String errorMessage = String.format(
                    "Could not create alias for %s, as alias zone does not exist.",
                    originalEntity.getAliasDescription()
            );
            throw new EntityAliasFailedException(errorMessage, HttpStatus.UNPROCESSABLE_ENTITY.value(), e);
        }

        // create new alias entity in alias zid
        final T persistedAliasEntity = createEntity(aliasEntity, originalEntity.getAliasZid());

        // update alias ID in original entity
        originalEntity.setAliasId(persistedAliasEntity.getId());
        return updateEntity(originalEntity, originalEntity.getZoneId());
    }

    private T buildAliasEntity(final T originalEntity) {
        final T aliasEntity = cloneEntity(originalEntity);
        aliasEntity.setAliasId(originalEntity.getId());
        aliasEntity.setAliasZid(originalEntity.getZoneId());
        setZoneId(aliasEntity, originalEntity.getAliasZid());
        setId(aliasEntity, null); // will be set later
        return aliasEntity;
    }

    protected abstract void setId(final T entity, final String id);

    protected abstract void setZoneId(final T entity, final String zoneId);

    /**
     * Build a clone of the given entity. The properties 'aliasId', 'aliasZid', 'id' and 'zoneId' are not required to be
     * cloned, since they will be adjusted afterward anyway.
     */
    protected abstract T cloneEntity(final T originalEntity);

    public final Optional<T> retrieveAliasEntity(final T originalEntity) {
        return retrieveEntity(originalEntity.getAliasId(), originalEntity.getAliasZid());
    }

    protected abstract Optional<T> retrieveEntity(final String id, final String zoneId);

    protected abstract T updateEntity(final T entity, final String zoneId);

    protected abstract T createEntity(final T entity, final String zoneId) throws EntityAliasFailedException;

    protected static <T extends EntityWithAlias> boolean isValidAliasPair(final T entity1, final T entity2) {
        // check if both entities have an alias
        final boolean entity1HasAlias = hasText(entity1.getAliasId()) && hasText(entity1.getAliasZid());
        final boolean entity2HasAlias = hasText(entity2.getAliasId()) && hasText(entity2.getAliasZid());
        if (!entity1HasAlias || !entity2HasAlias) {
            return false;
        }

        // check if they reference each other
        final boolean entity1ReferencesEntity2 = Objects.equals(entity1.getAliasId(), entity2.getId()) &&
                Objects.equals(entity1.getAliasZid(), entity2.getZoneId());
        final boolean entity2ReferencesEntity1 = Objects.equals(entity2.getAliasId(), entity1.getId()) &&
                Objects.equals(entity2.getAliasZid(), entity1.getZoneId());
        return entity1ReferencesEntity2 && entity2ReferencesEntity1;
    }
}
