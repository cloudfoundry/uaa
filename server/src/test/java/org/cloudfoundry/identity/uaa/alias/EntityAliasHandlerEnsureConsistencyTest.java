package org.cloudfoundry.identity.uaa.alias;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

import java.util.UUID;

import org.cloudfoundry.identity.uaa.EntityWithAlias;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.lang.Nullable;

public abstract class EntityAliasHandlerEnsureConsistencyTest<T extends EntityWithAlias> {
    protected abstract EntityAliasHandler<T> buildAliasHandler(final boolean aliasEntitiesEnabled);
    protected abstract T shallowCloneEntity(final T entity);
    protected abstract T buildEntityWithAliasProperties(@Nullable final String aliasId, @Nullable final String aliasZid);
    protected abstract void changeNonAliasProperties(final T entity);
    protected abstract void arrangeZoneDoesNotExist(final String zoneId);
    protected abstract void mockUpdateEntity(final String zoneId);
    protected abstract void mockCreateEntity(final String newId, final String zoneId);
    protected abstract void arrangeEntityDoesNotExist(final String id, final String zoneId);

    protected final String customZoneId = UUID.randomUUID().toString();

    private abstract class Base {
        protected EntityAliasHandler<T> aliasHandler;

        @BeforeEach
        final void setUp() {
            final boolean aliasEntitiesEnabled = isAliasFeatureEnabled();
            this.aliasHandler = buildAliasHandler(aliasEntitiesEnabled);
        }

        protected abstract boolean isAliasFeatureEnabled();
    }

    private abstract class NoExistingAliasBase extends Base {
        @Test
        final void shouldIgnore_AliasZidEmptyInOriginalIdp() {
            final T originalEntity = buildEntityWithAliasProperties(null, null);
            final T existingEntity = shallowCloneEntity(originalEntity);
            changeNonAliasProperties(existingEntity);

            final T result = aliasHandler.ensureConsistencyOfAliasEntity(originalEntity, existingEntity);
            assertThat(result).isEqualTo(originalEntity);
        }
    }

    protected abstract class NoExistingAlias_AliasFeatureEnabled extends NoExistingAliasBase {
        @Override
        protected final boolean isAliasFeatureEnabled() {
            return true;
        }

        @Test
        final void shouldThrow_WhenAliasZidSetButZoneDoesNotExist() {
            final T existingEntity = buildEntityWithAliasProperties(null, null);
            final T originalEntity = shallowCloneEntity(existingEntity);
            originalEntity.setAliasZid(customZoneId);

            arrangeZoneDoesNotExist(customZoneId);

            assertThatExceptionOfType(EntityAliasFailedException.class).isThrownBy(() ->
                    aliasHandler.ensureConsistencyOfAliasEntity(originalEntity, existingEntity)
            );
        }

        @Test
        final void shouldCreateNewAliasIdp_WhenAliasZoneExistsAndAliasPropertiesAreSet() {
            final T existingEntity = buildEntityWithAliasProperties(null, null);
            final T originalEntity = shallowCloneEntity(existingEntity);
            originalEntity.setAliasZid(customZoneId);

            final String aliasEntityId = UUID.randomUUID().toString();
            mockCreateEntity(aliasEntityId, customZoneId);
            mockUpdateEntity(UAA);

            final T result = aliasHandler.ensureConsistencyOfAliasEntity(
                    originalEntity,
                    existingEntity
            );
            assertThat(result.getAliasId()).isEqualTo(aliasEntityId);
            assertThat(result.getAliasZid()).isEqualTo(customZoneId);
        }
    }

    protected abstract class NoExistingAlias_AliasFeatureDisabled extends NoExistingAliasBase {
        @Override
        protected final boolean isAliasFeatureEnabled() {
            return false;
        }

        @Test
        final void shouldThrow_WhenAliasZidSet() {
            final T existingEntity = buildEntityWithAliasProperties(null, null);
            final T originalEntity = shallowCloneEntity(existingEntity);
            originalEntity.setAliasZid(customZoneId);

            assertThatIllegalStateException().isThrownBy(() ->
                    aliasHandler.ensureConsistencyOfAliasEntity(originalEntity, existingEntity)
            ).withMessage("Trying to create a new alias while alias feature is disabled.");
        }
    }

    protected abstract class ExistingAlias_AliasFeatureEnabled extends Base {
        @Override
        protected final boolean isAliasFeatureEnabled() {
            return true;
        }

        @Test
        final void shouldThrow_WhenReferencedAliasEntityAndAliasZoneDoNotExist() {
            final String aliasIdpId = UUID.randomUUID().toString();

            final T existingEntity = buildEntityWithAliasProperties(aliasIdpId, customZoneId);
            final T originalEntity = shallowCloneEntity(existingEntity);
            changeNonAliasProperties(originalEntity);

            arrangeEntityDoesNotExist(aliasIdpId, customZoneId);
            arrangeZoneDoesNotExist(customZoneId);

            assertThatExceptionOfType(EntityAliasFailedException.class).isThrownBy(() ->
                    aliasHandler.ensureConsistencyOfAliasEntity(originalEntity, existingEntity)
            );
        }
    }

    protected abstract class ExistingAlias_AliasFeatureDisabled extends Base {
        @Override
        protected final boolean isAliasFeatureEnabled() {
            return false;
        }

        @Test
        final void shouldThrow_EvenIfNoAliasPropertyIsChanged() {
            final T existingEntity = buildEntityWithAliasProperties(UUID.randomUUID().toString(), customZoneId);

            final T originalEntity = shallowCloneEntity(existingEntity);
            changeNonAliasProperties(originalEntity);

            assertThatIllegalStateException().isThrownBy(() ->
                    aliasHandler.ensureConsistencyOfAliasEntity(originalEntity, existingEntity)
            ).withMessage("Performing update on entity with alias while alias feature is disabled.");
        }

        @Test
        final void shouldThrow_AliasPropertiesSetToNull() {
            final T existingEntity = buildEntityWithAliasProperties(UUID.randomUUID().toString(), customZoneId);

            final T originalEntity = shallowCloneEntity(existingEntity);
            changeNonAliasProperties(originalEntity);
            originalEntity.setAliasId(null);
            originalEntity.setAliasZid(null);

            assertThatIllegalStateException().isThrownBy(() ->
                    aliasHandler.ensureConsistencyOfAliasEntity(originalEntity, existingEntity)
            ).withMessage("Performing update on entity with alias while alias feature is disabled.");
        }
    }
}
