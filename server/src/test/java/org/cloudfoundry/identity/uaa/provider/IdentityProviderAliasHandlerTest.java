package org.cloudfoundry.identity.uaa.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.IdentityProviderAliasHandler.IDP_TYPES_ALIAS_SUPPORTED;
import static org.mockito.Mockito.when;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.lang.Nullable;

@ExtendWith(MockitoExtension.class)
class IdentityProviderAliasHandlerTest {
    @Mock
    private IdentityZoneProvisioning identityZoneProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;

    @Nested
    class Validation {
        private static final String CUSTOM_ZONE_ID = UUID.randomUUID().toString();

        abstract class AliasFeatureSwitchTestBase {
            protected IdentityProviderAliasHandler aliasHandler;

            @BeforeEach
            void setUp() {
                final boolean aliasEntitiesEnabled = isAliasFeatureEnabled();
                this.aliasHandler = new IdentityProviderAliasHandler(
                        identityZoneProvisioning,
                        identityProviderProvisioning,
                        aliasEntitiesEnabled
                );
            }

            protected abstract boolean isAliasFeatureEnabled();
        }

        @Nested
        class ExistingAlias {
            @Nested
            class AliasFeatureEnabled extends AliasFeatureSwitchTestBase {
                @Override
                protected boolean isAliasFeatureEnabled() {
                    return true;
                }

                @Test
                void shouldThrow_AliasIdEmptyInExisting() {
                    final IdentityProvider<?> existingIdp = getExampleIdp(null, CUSTOM_ZONE_ID);

                    final IdentityProvider<?> requestBody = getExampleIdp(null, CUSTOM_ZONE_ID);
                    requestBody.setName("some-new-name");

                    assertThatIllegalStateException().isThrownBy(() ->
                            aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)
                    );
                }

                @Test
                void shouldReturnFalse_AliasPropsChangedInReqBody() {
                    final String initialAliasId = UUID.randomUUID().toString();
                    final String initialAliasZid = CUSTOM_ZONE_ID;

                    final IdentityProvider<?> existingIdp = getExampleIdp(initialAliasId, initialAliasZid);

                    final IdentityProvider<?> requestBody = getExampleIdp(initialAliasId, initialAliasZid);
                    requestBody.setName("some-new-name");

                    final Runnable resetRequestBody = () -> {
                        requestBody.setAliasId(initialAliasId);
                        requestBody.setAliasZid(initialAliasZid);
                    };

                    // (1) only alias ID changed
                    requestBody.setAliasId(UUID.randomUUID().toString());
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                    resetRequestBody.run();

                    // (2) only alias ZID changed
                    requestBody.setAliasZid(UUID.randomUUID().toString());
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                    resetRequestBody.run();

                    // (3) both changed
                    requestBody.setAliasId(UUID.randomUUID().toString());
                    requestBody.setAliasZid(UUID.randomUUID().toString());
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                    resetRequestBody.run();

                    // (4) only alias ID removed
                    requestBody.setAliasId(null);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                    resetRequestBody.run();

                    // (5) only alias ZID removed
                    requestBody.setAliasZid(null);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                    resetRequestBody.run();

                    // (6) both removed
                    requestBody.setAliasId(null);
                    requestBody.setAliasZid(null);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                }

                @Test
                void shouldReturnTrue_AliasPropsUnchangedInReqBody() {
                    final String aliasId = UUID.randomUUID().toString();
                    final IdentityProvider<?> existingIdp = getExampleIdp(aliasId, CUSTOM_ZONE_ID);

                    final IdentityProvider<?> requestBody = getExampleIdp(aliasId, CUSTOM_ZONE_ID);
                    requestBody.setName("some-new-name");

                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isTrue();
                }
            }

            @Nested
            class AliasFeatureDisabled extends AliasFeatureSwitchTestBase {
                @Override
                protected boolean isAliasFeatureEnabled() {
                    return false;
                }

                @Test
                void shouldReturnFalse_NotBothAliasPropsEmptyInReqBody() {
                    final String initialAliasId = UUID.randomUUID().toString();
                    final String initialAliasZid = CUSTOM_ZONE_ID;

                    final IdentityProvider<?> existingIdp = getExampleIdp(initialAliasId, initialAliasZid);

                    // (1) both alias props left unchanged
                    IdentityProvider<?> requestBody = getExampleIdp(initialAliasId, initialAliasZid);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();

                    // (2) alias ID unchanged, alias ZID changed
                    requestBody = getExampleIdp(initialAliasId, "some-other-zid");
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();

                    // (3) alias ID unchanged, alias ZID removed
                    requestBody = getExampleIdp(initialAliasId, null);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();

                    // (4) alias ID changed, alias ZID unchanged
                    requestBody = getExampleIdp("some-other-id", initialAliasZid);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();

                    // (5) alias ID changed, alias ZID changed
                    requestBody = getExampleIdp("some-other-id", "some-other-zid");
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();

                    // (6) alias ID changed, alias ZID removed
                    requestBody = getExampleIdp("some-other-id", null);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();

                    // (7) alias ID removed, alias ZID unchanged
                    requestBody = getExampleIdp(null, initialAliasZid);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();

                    // (8) alias ID removed, alias ZID changed
                    requestBody = getExampleIdp(null, "some-other-zid");
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                }

                @Test
                void shouldReturnTrue_BothAliasPropsEmptyInReqBody() {
                    final IdentityProvider<?> existingIdp = getExampleIdp(
                            UUID.randomUUID().toString(),
                            CUSTOM_ZONE_ID
                    );
                    final IdentityProvider<?> requestBody = getExampleIdp(null, null);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isTrue();
                }
            }
        }

        @Nested
        class NoExistingAlias {
            abstract class NoExistingAliasTestBase extends AliasFeatureSwitchTestBase {
                @ParameterizedTest
                @MethodSource("existingIdpArgumentNoExistingAlias")
                void shouldReturnFalse_AliasIdSetInReqBody(final IdentityProvider<?> existingIdp) {
                    final IdentityProvider<?> requestBody = getExampleIdp(UUID.randomUUID().toString(), null);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                }

                @ParameterizedTest
                @MethodSource("existingIdpArgumentNoExistingAlias")
                void shouldReturnTrue_BothAliasPropsEmptyInReqBody(final IdentityProvider<?> existingIdp) {
                    final IdentityProvider<?> requestBody = getExampleIdp(null, null);
                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isTrue();
                }

                /**
                 * Provider for the 'existingIdp' argument for cases where no alias should exist, i.e., either an
                 * original IdP with empty alias properties or no existing IdP.
                 */
                protected static Stream<IdentityProvider<?>> existingIdpArgumentNoExistingAlias() {
                    return Stream.of(
                            getExampleIdp(null, null), // update of existing IdP without alias
                            null // creation of new IdP
                    );
                }
            }

            @Nested
            class AliasFeatureEnabled extends NoExistingAliasTestBase {
                @Override
                protected boolean isAliasFeatureEnabled() {
                    return true;
                }

                @ParameterizedTest
                @MethodSource("existingIdpArgumentNoExistingAlias")
                void shouldReturnFalse_AliasZoneDoesNotExist(final IdentityProvider<?> existingIdp) {
                    final String aliasZid = UUID.randomUUID().toString();
                    arrangeZoneDoesNotExist(aliasZid);

                    final IdentityProvider<?> requestBody = getExampleIdp(null, aliasZid);

                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                }

                @ParameterizedTest
                @MethodSource("existingIdpArgumentNoExistingAlias")
                void shouldReturnFalse_ZidAndAliasZidAreEqual(final IdentityProvider<?> existingIdp) {
                    final String aliasZid = UUID.randomUUID().toString();
                    arrangeZoneExists(aliasZid);

                    final IdentityProvider<?> requestBody = getExampleIdp(null, aliasZid);
                    requestBody.setIdentityZoneId(aliasZid);

                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                }

                @ParameterizedTest
                @MethodSource("existingIdpArgumentNoExistingAlias")
                void shouldReturnFalse_NeitherOfZidAndAliasZidIsUaa(final IdentityProvider<?> existingIdp) {
                    final String aliasZid = UUID.randomUUID().toString();
                    arrangeZoneExists(aliasZid);

                    final IdentityProvider<?> requestBody = getExampleIdp(null, aliasZid);
                    requestBody.setIdentityZoneId(UUID.randomUUID().toString());

                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                }

                @ParameterizedTest
                @MethodSource
                void shouldReturnFalse_AliasNotSupportedForIdpType(
                        final IdentityProvider<?> existingIdp,
                        final String typeAliasNotSupported
                ) {
                    final String aliasZid = UUID.randomUUID().toString();
                    arrangeZoneExists(aliasZid);

                    final IdentityProvider<?> requestBody = getExampleIdp(null, aliasZid);
                    requestBody.setIdentityZoneId(UAA);
                    requestBody.setType(typeAliasNotSupported);

                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                }

                private static Stream<Arguments> shouldReturnFalse_AliasNotSupportedForIdpType() {
                    final Set<String> typesAliasNotSupported = Set.of(UNKNOWN, LDAP, UAA, KEYSTONE);
                    return existingIdpArgumentNoExistingAlias().flatMap(existingIdpArgument ->
                            typesAliasNotSupported.stream().map(typeAliasNotSupported ->
                                    Arguments.of(existingIdpArgument, typeAliasNotSupported)
                            ));
                }

                @ParameterizedTest
                @MethodSource
                void shouldReturnTrue_AliasSupportedForIdpType(
                        final IdentityProvider<?> existingIdp,
                        final String typeAliasSupported
                ) {
                    final String aliasZid = UUID.randomUUID().toString();
                    arrangeZoneExists(aliasZid);

                    final IdentityProvider<?> requestBody = getExampleIdp(null, aliasZid);
                    requestBody.setIdentityZoneId(UAA);
                    requestBody.setType(typeAliasSupported);

                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isTrue();
                }

                private static Stream<Arguments> shouldReturnTrue_AliasSupportedForIdpType() {
                    return existingIdpArgumentNoExistingAlias().flatMap(existingIdpArgument ->
                            IDP_TYPES_ALIAS_SUPPORTED.stream().map(typeAliasSupported ->
                                    Arguments.of(existingIdpArgument, typeAliasSupported)
                            ));
                }
            }

            @Nested
            class AliasFeatureDisabled extends NoExistingAliasTestBase {
                @Override
                protected boolean isAliasFeatureEnabled() {
                    return false;
                }

                @Test
                void shouldReturnFalse_OnlyAliasZidSetInReqBody() {
                    final String initialAliasZid = CUSTOM_ZONE_ID;

                    final IdentityProvider<?> existingIdp = getExampleIdp(
                            UUID.randomUUID().toString(),
                            initialAliasZid
                    );
                    final IdentityProvider<?> requestBody = getExampleIdp(null, initialAliasZid);

                    assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
                }
            }
        }

        private void arrangeZoneExists(final String zoneId) {
            when(identityZoneProvisioning.retrieve(zoneId)).thenReturn(null);
        }

        private void arrangeZoneDoesNotExist(final String zoneId) {
            when(identityZoneProvisioning.retrieve(zoneId))
                    .thenThrow(new ZoneDoesNotExistsException("Zone does not exist."));
        }

        private static IdentityProvider<?> getExampleIdp(
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
            return idp;
        }
    }
}