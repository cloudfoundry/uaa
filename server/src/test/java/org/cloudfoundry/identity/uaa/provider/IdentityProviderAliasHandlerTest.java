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
    private IdentityProviderAliasHandler aliasHandler;

    @BeforeEach
    void setUp() {
        aliasHandler = new IdentityProviderAliasHandler(
                identityZoneProvisioning,
                identityProviderProvisioning,
                true
        );
    }

    @Nested
    class Validation {
        @Nested
        class ExistingAlias {
            private static final String CUSTOM_ZONE_ID = UUID.randomUUID().toString();

            @Test
            void shouldThrow_WhenExistingIdpHasAliasZidSetButNotAliasId() {
                final IdentityProvider<?> existingIdp = getExampleIdp(null, CUSTOM_ZONE_ID);

                final IdentityProvider<?> requestBody = getExampleIdp(null, CUSTOM_ZONE_ID);
                requestBody.setName("some-new-name");

                assertThatIllegalStateException().isThrownBy(() ->
                        aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)
                );
            }

            @Test
            void shouldReturnFalse_WhenAliasPropertiesAreChanged() {
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
            void shouldReturnTrue_AliasPropertiesUnchanged() {
                final String aliasId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = getExampleIdp(aliasId, CUSTOM_ZONE_ID);

                final IdentityProvider<?> requestBody = getExampleIdp(aliasId, CUSTOM_ZONE_ID);
                requestBody.setName("some-new-name");

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isTrue();
            }
        }

        @Nested
        class NoExistingAlias {

            @ParameterizedTest
            @MethodSource("existingIdpArgument")
            void shouldReturnFalse_WhenAliasIdIsSet(final IdentityProvider<?> existingIdp) {
                final IdentityProvider<?> requestBody = getExampleIdp(UUID.randomUUID().toString(), null);
                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
            }

            @ParameterizedTest
            @MethodSource("existingIdpArgument")
            void shouldReturnTrue_WhenBothAliasFieldsAreNotSet(final IdentityProvider<?> existingIdp) {
                final IdentityProvider<?> requestBody = getExampleIdp(null, null);
                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isTrue();
            }

            @ParameterizedTest
            @MethodSource("existingIdpArgument")
            void shouldReturnFalse_WhenOnlyAliasZidSetButZoneDoesNotExist(final IdentityProvider<?> existingIdp) {
                final String aliasZid = UUID.randomUUID().toString();
                arrangeZoneDoesNotExist(aliasZid);

                final IdentityProvider<?> requestBody = getExampleIdp(null, aliasZid);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
            }

            @ParameterizedTest
            @MethodSource("existingIdpArgument")
            void shouldReturnFalse_WhenIdzAndAliasZidAreEqual(final IdentityProvider<?> existingIdp) {
                final String aliasZid = UUID.randomUUID().toString();
                arrangeZoneExists(aliasZid);

                final IdentityProvider<?> requestBody = getExampleIdp(null, aliasZid);
                requestBody.setIdentityZoneId(aliasZid);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
            }

            @ParameterizedTest
            @MethodSource("existingIdpArgument")
            void shouldReturnFalse_WhenNeitherIdzNorAliasZidIsUaa(final IdentityProvider<?> existingIdp) {
                final String aliasZid = UUID.randomUUID().toString();
                arrangeZoneExists(aliasZid);

                final IdentityProvider<?> requestBody = getExampleIdp(null, aliasZid);
                requestBody.setIdentityZoneId(UUID.randomUUID().toString());

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingIdp)).isFalse();
            }

            @ParameterizedTest
            @MethodSource
            void shouldReturnFalse_WhenAliasIsNotSupportedForIdpType(
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

            private static Stream<Arguments> shouldReturnFalse_WhenAliasIsNotSupportedForIdpType() {
                final Set<String> typesAliasNotSupported = Set.of(UNKNOWN, LDAP, UAA, KEYSTONE);
                return existingIdpArgument().flatMap(existingIdpArgument ->
                        typesAliasNotSupported.stream().map(typeAliasNotSupported ->
                                Arguments.of(existingIdpArgument, typeAliasNotSupported)
                        ));
            }

            @ParameterizedTest
            @MethodSource
            void shouldReturnTrue_SuccessCase(
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

            private static Stream<Arguments> shouldReturnTrue_SuccessCase() {
                return existingIdpArgument().flatMap(existingIdpArgument ->
                        IDP_TYPES_ALIAS_SUPPORTED.stream().map(typeAliasSupported ->
                                Arguments.of(existingIdpArgument, typeAliasSupported)
                        ));
            }

            private static Stream<IdentityProvider<?>> existingIdpArgument() {
                return Stream.of(
                        getExampleIdp(null, null), // update of existing IdP without alias
                        null // creation of new IdP
                );
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