package org.cloudfoundry.identity.uaa.alias;

import org.cloudfoundry.identity.uaa.EntityWithAlias;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.springframework.lang.Nullable;

import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

public abstract class EntityAliasHandlerEnsureConsistencyTest<T extends EntityWithAlias> {
    protected abstract EntityAliasHandler<T> buildAliasHandler(final boolean aliasEntitiesEnabled);

    protected abstract T shallowCloneEntity(final T entity);

    protected abstract T buildEntityWithAliasProperties(@Nullable final String aliasId, @Nullable final String aliasZid);

    /**
     * Change one or more properties (but neither 'aliasId' nor 'aliasZid') of the given entity.
     */
    protected abstract void changeNonAliasProperties(final T entity);

    protected abstract void arrangeZoneDoesNotExist(final String zoneId);

    /**
     * Mock updating entities by always returning the entity passed as an argument to the update method.
     */
    protected abstract void mockUpdateEntity(final String zoneId);

    /**
     * Mock creating entities by taking the entity passed as an argument to the create method and setting the given new
     * ID.
     */
    protected abstract void mockCreateEntity(final String newId, final String zoneId);

    protected abstract void arrangeEntityExists(final String id, final String zoneId, final T entity);

    protected abstract void arrangeEntityDoesNotExist(final String id, final String zoneId);

    /**
     * Check whether the given two entities are equal. This method is required since the {@link ScimUser} class does not
     * implement an {@code equals} method that is precise enough.
     */
    protected abstract boolean entitiesAreEqual(final T entity1, final T entity2);

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
        final void shouldIgnore_AliasZidEmptyInOriginalEntity() {
            final T originalEntity = buildEntityWithAliasProperties(null, null);
            final T existingEntity = shallowCloneEntity(originalEntity);
            changeNonAliasProperties(existingEntity);

            final T result = aliasHandler.ensureConsistencyOfAliasEntity(originalEntity, existingEntity);
            assertThat(entitiesAreEqual(result, originalEntity)).isTrue();
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
        final void shouldCreateNewAliasEntity_WhenAliasZoneExistsAndAliasPropertiesAreSet() {
            final T existingEntity = buildEntityWithAliasProperties(null, null);
            final T originalEntity = shallowCloneEntity(existingEntity);
            originalEntity.setAliasZid(customZoneId);

            final String aliasId = UUID.randomUUID().toString();
            mockCreateEntity(aliasId, customZoneId);
            mockUpdateEntity(UAA);

            final T result = aliasHandler.ensureConsistencyOfAliasEntity(
                    originalEntity,
                    existingEntity
            );
            assertThat(result.getAliasId()).isEqualTo(aliasId);
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
            final String aliasId = UUID.randomUUID().toString();

            final T existingEntity = buildEntityWithAliasProperties(aliasId, customZoneId);
            final T originalEntity = shallowCloneEntity(existingEntity);
            changeNonAliasProperties(originalEntity);

            arrangeEntityDoesNotExist(aliasId, customZoneId);
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

    protected static class EntityWithAliasMatcher<T extends EntityWithAlias> implements ArgumentMatcher<T> {
        private final String zoneId;
        private final String id;
        private final String aliasId;
        private final String aliasZid;

        public EntityWithAliasMatcher(final String zoneId, final String id, final String aliasId, final String aliasZid) {
            this.zoneId = zoneId;
            this.id = id;
            this.aliasId = aliasId;
            this.aliasZid = aliasZid;
        }

        @Override
        public boolean matches(final T argument) {
            return Objects.equals(id, argument.getId()) && Objects.equals(zoneId, argument.getZoneId())
                    && Objects.equals(aliasId, argument.getAliasId()) && Objects.equals(aliasZid, argument.getAliasZid());
        }
    }
}
