package org.cloudfoundry.identity.uaa.alias;

import org.cloudfoundry.identity.uaa.EntityWithAlias;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.cloudfoundry.identity.uaa.alias.EntityAliasHandlerValidationTest.NoExistingAliasBase.ExistingEntityArgument.ENTITY_WITH_EMPTY_ALIAS_PROPS;

public abstract class EntityAliasHandlerValidationTest<T extends EntityWithAlias> {
    private static final String CUSTOM_ZONE_ID = UUID.randomUUID().toString();

    protected abstract EntityAliasHandler<T> buildAliasHandler(final boolean aliasEntitiesEnabled);

    protected abstract T buildEntityWithAliasProps(
            @Nullable final String zoneId,
            @Nullable final String aliasId,
            @Nullable final String aliasZid
    );

    protected abstract void changeNonAliasProperties(@NonNull final T entity);

    protected abstract void setZoneId(@NonNull final T entity, @Nullable final String zoneId);

    protected abstract void arrangeZoneExists(@NonNull final String zoneId);

    protected abstract void arrangeZoneDoesNotExist(@NonNull final String zoneId);

    protected abstract class Base {
        protected EntityAliasHandler<T> aliasHandler;

        @BeforeEach
        final void setUp() {
            final boolean aliasEntitiesEnabled = isAliasFeatureEnabled();
            this.aliasHandler = buildAliasHandler(aliasEntitiesEnabled);
        }

        protected abstract boolean isAliasFeatureEnabled();
    }

    protected abstract class NoExistingAliasBase extends Base {
        @ParameterizedTest
        @EnumSource
        final void shouldReturnFalse_AliasIdSetInReqBody(final ExistingEntityArgument existingEntityArg) {
            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), UUID.randomUUID().toString(), null);
            final T existingEntity = resolveExistingEntityArgument(existingEntityArg);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
        }

        @ParameterizedTest
        @EnumSource
        final void shouldReturnTrue_BothAliasPropsEmptyInReqBody(final ExistingEntityArgument existingEntityArg) {
            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, null);
            final T existingEntity = resolveExistingEntityArgument(existingEntityArg);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isTrue();
        }

        /**
         * For some endpoints, we allow the identity zone ID of to be empty in the request body. However, the field is
         * required during alias validation. We therefore rely on the endpoint methods to set the identity zone ID to
         * the one resolved from the token.
         */
        @ParameterizedTest
        @EnumSource
        final void shouldThrowIllegalArgumentException_ZoneIdEmptyInReqBody(final ExistingEntityArgument existingEntityArg) {
            // alias property values are not important here, the zoneId is checked before them
            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, null);
            setZoneId(requestBody, null);

            final T existingEntity = resolveExistingEntityArgument(existingEntityArg);
            assertThatIllegalArgumentException().isThrownBy(() ->
                    aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)
            ).withMessage("The zone ID of the request body must not be empty.");
        }

        protected final T resolveExistingEntityArgument(@NonNull final ExistingEntityArgument existingEntityArgument) {
            if (existingEntityArgument == ENTITY_WITH_EMPTY_ALIAS_PROPS) {
                return buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, null);
            }
            return null;
        }

        /**
         * Provider for the 'existingEntity' argument for cases where no alias should exist, i.e., either an original
         * entity with empty alias properties or no existing entity.
         */
        protected enum ExistingEntityArgument {
            NULL,
            ENTITY_WITH_EMPTY_ALIAS_PROPS
        }
    }

    protected abstract class ExistingAlias_AliasFeatureDisabled extends Base {
        @Override
        protected final boolean isAliasFeatureEnabled() {
            return false;
        }

        @Test
        final void shouldReturnFalse_UpdatesOfEntitiesWithExistingAliasForbidden() {
            final String initialAliasId = UUID.randomUUID().toString();
            final String initialAliasZid = CUSTOM_ZONE_ID;

            final T existingEntity = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), initialAliasId, initialAliasZid);

            // (1) both alias props left unchanged
            T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), initialAliasId, initialAliasZid);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();

            // (2) alias ID unchanged, alias ZID changed
            requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), initialAliasId, "some-other-zid");
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();

            // (3) alias ID unchanged, alias ZID removed
            requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), initialAliasId, null);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();

            // (4) alias ID changed, alias ZID unchanged
            requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), "some-other-id", initialAliasZid);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();

            // (5) alias ID changed, alias ZID changed
            requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), "some-other-id", "some-other-zid");
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();

            // (6) alias ID changed, alias ZID removed
            requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), "some-other-id", null);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();

            // (7) alias ID removed, alias ZID unchanged
            requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, initialAliasZid);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();

            // (8) alias ID removed, alias ZID changed
            requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, "some-other-zid");
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();

            // (9) alias ID removed, alias ZID removed
            requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, null);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
        }

        @Test
        final void shouldReturnFalse_DefaultSetting() {
            AliasEntitiesConfig aliasEntitiesConfig = new AliasEntitiesConfig();
            assertThat(aliasEntitiesConfig.aliasEntitiesEnabled(false)).isFalse();
        }
    }

    protected abstract class ExistingAlias_AliasFeatureEnabled extends Base {
        @Override
        protected final boolean isAliasFeatureEnabled() {
            return true;
        }

        @Test
        final void shouldThrow_AliasIdEmptyInExisting() {
            final T existingEntity = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, CUSTOM_ZONE_ID);

            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, CUSTOM_ZONE_ID);
            changeNonAliasProperties(requestBody);

            assertThatIllegalStateException().isThrownBy(() ->
                    aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)
            );
        }

        @Test
        final void shouldReturnFalse_AliasPropsChangedInReqBody() {
            final String initialAliasId = UUID.randomUUID().toString();
            final String initialAliasZid = CUSTOM_ZONE_ID;

            final T existingEntity = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), initialAliasId, initialAliasZid);

            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), initialAliasId, initialAliasZid);
            changeNonAliasProperties(requestBody);

            final Runnable resetRequestBody = () -> {
                requestBody.setAliasId(initialAliasId);
                requestBody.setAliasZid(initialAliasZid);
            };

            // (1) only alias ID changed
            requestBody.setAliasId(UUID.randomUUID().toString());
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
            resetRequestBody.run();

            // (2) only alias ZID changed
            requestBody.setAliasZid(UUID.randomUUID().toString());
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
            resetRequestBody.run();

            // (3) both changed
            requestBody.setAliasId(UUID.randomUUID().toString());
            requestBody.setAliasZid(UUID.randomUUID().toString());
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
            resetRequestBody.run();

            // (4) only alias ID removed
            requestBody.setAliasId(null);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
            resetRequestBody.run();

            // (5) only alias ZID removed
            requestBody.setAliasZid(null);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
            resetRequestBody.run();

            // (6) both removed
            requestBody.setAliasId(null);
            requestBody.setAliasZid(null);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
        }

        @Test
        final void shouldReturnTrue_AliasPropsUnchangedInReqBody() {
            final String aliasId = UUID.randomUUID().toString();
            final T existingEntity = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), aliasId, CUSTOM_ZONE_ID);

            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), aliasId, CUSTOM_ZONE_ID);
            changeNonAliasProperties(requestBody);

            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isTrue();
        }
    }
    protected abstract class NoExistingAlias_AliasFeatureEnabled extends NoExistingAliasBase {
        @Override
        protected final boolean isAliasFeatureEnabled() {
            return true;
        }

        @ParameterizedTest
        @EnumSource
        final void shouldReturnFalse_AliasZoneDoesNotExist(final ExistingEntityArgument existingEntityArg) {
            final String aliasZid = UUID.randomUUID().toString();
            arrangeZoneDoesNotExist(aliasZid);

            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, aliasZid);

            final T existingEntity = resolveExistingEntityArgument(existingEntityArg);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
        }

        @ParameterizedTest
        @EnumSource
        final void shouldReturnFalse_ZidAndAliasZidAreEqual(final ExistingEntityArgument existingEntityArg) {
            final String aliasZid = UUID.randomUUID().toString();
            arrangeZoneExists(aliasZid);

            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, aliasZid);
            setZoneId(requestBody, aliasZid);

            final T existingEntity = resolveExistingEntityArgument(existingEntityArg);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
        }

        @ParameterizedTest
        @EnumSource
        final void shouldReturnFalse_NeitherOfZidAndAliasZidIsUaa(final ExistingEntityArgument existingEntityArg) {
            final String aliasZid = UUID.randomUUID().toString();
            arrangeZoneExists(aliasZid);

            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, aliasZid);
            setZoneId(requestBody, UUID.randomUUID().toString());

            final T existingEntity = resolveExistingEntityArgument(existingEntityArg);
            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
        }
    }

    protected abstract class NoExistingAlias_AliasFeatureDisabled extends NoExistingAliasBase {
        @Override
        protected final boolean isAliasFeatureEnabled() {
            return false;
        }

        @Test
        final void shouldReturnFalse_OnlyAliasZidSetInReqBody() {
            final String initialAliasZid = CUSTOM_ZONE_ID;

            final T existingEntity = buildEntityWithAliasProps(
                    IdentityZone.getUaaZoneId(),
                    UUID.randomUUID().toString(),
                    initialAliasZid
            );
            final T requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, initialAliasZid);

            assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingEntity)).isFalse();
        }
    }
}