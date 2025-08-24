package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.alias.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandlerValidationTest;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.IdentityProviderAliasHandler.IDP_TYPES_ALIAS_SUPPORTED;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class IdentityProviderAliasHandlerValidationTest extends EntityAliasHandlerValidationTest<IdentityProvider<?>> {
    @Mock
    private IdentityZoneProvisioning identityZoneProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;

    @Override
    protected EntityAliasHandler<IdentityProvider<?>> buildAliasHandler(final boolean aliasEntitiesEnabled) {
        return new IdentityProviderAliasHandler(
                identityZoneProvisioning,
                identityProviderProvisioning,
                aliasEntitiesEnabled
        );
    }

    @Override
    protected IdentityProvider<?> buildEntityWithAliasProps(
            @Nullable final String zoneId,
            @Nullable final String aliasId,
            @Nullable final String aliasZid
    ) {
        final IdentityProvider<AbstractIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setName("example");
        idp.setOriginKey("example");
        idp.setType(OIDC10);
        idp.setIdentityZoneId(UAA);
        idp.setAliasId(aliasId);
        idp.setAliasZid(aliasZid);
        setZoneId(idp, zoneId);
        return idp;
    }

    @Override
    protected void changeNonAliasProperties(@NonNull final IdentityProvider<?> entity) {
        entity.setName("some-new-name");
    }

    @Override
    protected void setZoneId(@NonNull final IdentityProvider<?> entity, @Nullable final String zoneId) {
        entity.setIdentityZoneId(zoneId);
    }

    @Override
    protected void arrangeZoneExists(@NonNull final String zoneId) {
        when(identityZoneProvisioning.retrieve(zoneId)).thenReturn(null);
    }

    @Override
    protected void arrangeZoneDoesNotExist(@NonNull final String zoneId) {
        when(identityZoneProvisioning.retrieve(zoneId))
                .thenThrow(new ZoneDoesNotExistsException("Zone does not exist."));
    }

    @Nested
    class NoExistingAlias {
        @Nested
        class AliasFeatureEnabled extends NoExistingAlias_AliasFeatureEnabled {
            @ParameterizedTest
            @MethodSource
            void shouldReturnFalse_AliasNotSupportedForIdpType(
                    final ExistingEntityArgument existingIdp,
                    final String typeAliasNotSupported
            ) {
                final String aliasZid = UUID.randomUUID().toString();
                arrangeZoneExists(aliasZid);

                final IdentityProvider<?> requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, aliasZid);
                requestBody.setIdentityZoneId(UAA);
                requestBody.setType(typeAliasNotSupported);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, resolveExistingEntityArgument(existingIdp))).isFalse();
            }

            private static Stream<Arguments> shouldReturnFalse_AliasNotSupportedForIdpType() {
                final Set<String> typesAliasNotSupported = Set.of(UNKNOWN, LDAP, UAA, KEYSTONE);
                return Arrays.stream(ExistingEntityArgument.values()).flatMap(existingEntityArgument ->
                        typesAliasNotSupported.stream().map(typeAliasNotSupported ->
                                Arguments.of(existingEntityArgument, typeAliasNotSupported)
                        ));
            }

            @ParameterizedTest
            @MethodSource
            void shouldReturnTrue_AliasSupportedForIdpType(
                    final ExistingEntityArgument existingIdp,
                    final String typeAliasSupported
            ) {
                final String aliasZid = UUID.randomUUID().toString();
                arrangeZoneExists(aliasZid);

                final IdentityProvider<?> requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, aliasZid);
                requestBody.setIdentityZoneId(UAA);
                requestBody.setType(typeAliasSupported);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, resolveExistingEntityArgument(existingIdp))).isTrue();
            }

            private static Stream<Arguments> shouldReturnTrue_AliasSupportedForIdpType() {
                return Arrays.stream(ExistingEntityArgument.values()).flatMap(existingEntityArgument ->
                        IDP_TYPES_ALIAS_SUPPORTED.stream().map(typeAliasSupported ->
                                Arguments.of(existingEntityArgument, typeAliasSupported)
                        ));
            }
        }

        @Nested
        class AliasFeatureDisabled extends NoExistingAlias_AliasFeatureDisabled {
            // all tests defined in superclass
        }
    }

    @Nested
    class ExistingAlias {
        @Nested
        class AliasFeatureEnabled extends ExistingAlias_AliasFeatureEnabled {
            // all tests defined in superclass
        }

        @Nested
        class AliasFeatureDisabled extends ExistingAlias_AliasFeatureDisabled {
            // all tests defined in superclass
        }
    }
}
