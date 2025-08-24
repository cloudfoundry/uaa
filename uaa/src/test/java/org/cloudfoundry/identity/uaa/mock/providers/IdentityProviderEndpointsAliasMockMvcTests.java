package org.cloudfoundry.identity.uaa.mock.providers;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderEndpoints;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

/**
 * Tests regarding the handling of "aliasId" and "aliasZid" properties of identity providers.
 */
@DefaultTestContext
class IdentityProviderEndpointsAliasMockMvcTests {
    private static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR = new AlphanumericRandomValueStringGenerator(8);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestClient testClient;

    @Autowired
    private WebApplicationContext webApplicationContext;

    private final Map<String, String> accessTokenCache = new HashMap<>();
    private IdentityZone customZone;
    private String adminToken;
    private String identityToken;
    private IdentityProviderAliasHandler idpEntityAliasHandler;
    private IdentityProviderEndpoints identityProviderEndpoints;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "");
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write");
        customZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

        idpEntityAliasHandler = requireNonNull(webApplicationContext.getBean(IdentityProviderAliasHandler.class));
        identityProviderEndpoints = requireNonNull(webApplicationContext.getBean(IdentityProviderEndpoints.class));
    }

    @Nested
    class Read {
        @Nested
        class AliasFeatureDisabled {
            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(false);
            }

            @AfterEach
            void tearDown() {
                arrangeAliasFeatureEnabled(true);
            }

            @Test
            void shouldStillReturnAliasPropertiesOfIdpsWithAliasCreatedBeforehand_UaaToCustomZone() throws Throwable {
                shouldStillReturnAliasPropertiesOfIdpsWithAliasCreatedBeforehand(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldStillReturnAliasPropertiesOfIdpsWithAliasCreatedBeforehand_CustomToUaaZone() throws Throwable {
                shouldStillReturnAliasPropertiesOfIdpsWithAliasCreatedBeforehand(customZone, IdentityZone.getUaa());
            }

            private void shouldStillReturnAliasPropertiesOfIdpsWithAliasCreatedBeforehand(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> existingIdp = executeWithTemporarilyEnabledAliasFeature(
                        true,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final List<IdentityProvider<?>> allIdps = readAllIdpsInZone(zone1);
                assertThat(allIdps).isNotNull();
                final Optional<IdentityProvider<?>> createdIdp = allIdps.stream()
                        .filter(it -> it.getOriginKey().equals(existingIdp.getOriginKey()))
                        .findFirst();
                assertThat(createdIdp).contains(existingIdp);
                assertThat(createdIdp.get().getAliasZid()).isEqualTo(zone2.getId());
            }
        }
    }

    @Nested
    class Create {
        abstract class CreateBase {
            private final boolean aliasFeatureEnabled;

            protected CreateBase(final boolean aliasFeatureEnabled) {
                this.aliasFeatureEnabled = aliasFeatureEnabled;
            }

            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(aliasFeatureEnabled);
            }

            @Test
            void shouldAccept_AliasPropertiesNotSet_UaaZone() throws Exception {
                shouldAccept_AliasPropertiesNotSet(IdentityZone.getUaa());
            }

            @Test
            void shouldAccept_AliasPropertiesNotSet_CustomZone() throws Exception {
                shouldAccept_AliasPropertiesNotSet(customZone);
            }

            private void shouldAccept_AliasPropertiesNotSet(final IdentityZone zone) throws Exception {
                final IdentityProvider<?> idp = buildOidcIdpWithAliasProperties(
                        zone.getId(),
                        null,
                        null
                );

                final IdentityProvider<?> createdIdp = createIdp(zone, idp);
                assertThat(createdIdp).isNotNull();
                assertThat(createdIdp.getAliasId()).isBlank();
                assertThat(createdIdp.getAliasZid()).isBlank();
            }

            @Test
            void shouldReject_AliasIdIsSet_UaaToCustomZone() throws Exception {
                shouldReject_AliasIdIsSet(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_AliasIdIsSet_CustomToUaaZone() throws Exception {
                shouldReject_AliasIdIsSet(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_AliasIdIsSet(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Exception {
                final String aliasId = UUID.randomUUID().toString();
                final IdentityProvider<?> idp = buildOidcIdpWithAliasProperties(zone1.getId(), aliasId, zone2.getId());
                shouldRejectCreation(zone1, idp, HttpStatus.UNPROCESSABLE_ENTITY);
            }
        }

        @Nested
        class AliasFeatureEnabled extends CreateBase {
            protected AliasFeatureEnabled() {
                super(true);
            }

            @Test
            void shouldAccept_CreateAliasIdp_UaaToCustomZone() throws Exception {
                shouldAccept_CreateAliasIdp(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldAccept_CreateAliasIdp_CustomToUaaZone() throws Exception {
                shouldAccept_CreateAliasIdp(customZone, IdentityZone.getUaa());
            }

            private void shouldAccept_CreateAliasIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
                // build IdP in zone1 with aliasZid set to zone2
                final IdentityProvider<?> provider = buildOidcIdpWithAliasProperties(zone1.getId(), null, zone2.getId());

                // create IdP in zone1
                final IdentityProvider<?> originalIdp = createIdp(zone1, provider);
                assertThat(originalIdp).isNotNull();
                assertThat(originalIdp.getAliasId()).isNotBlank();
                assertThat(originalIdp.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());

                // read alias IdP from zone2
                final String id = originalIdp.getAliasId();
                final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), id);
                assertThat(aliasIdp).isPresent();
                assertIdpReferencesOtherIdp(aliasIdp.get(), originalIdp);
                assertOtherPropertiesAreEqual(originalIdp, aliasIdp.get());

                // check if aliasId in first IdP is equal to the ID of the alias IdP
                assertThat(aliasIdp.get().getId()).isEqualTo(originalIdp.getAliasId());

                // check if both have the same non-empty relying party secret
                assertIdpAndAliasHaveSameRelyingPartySecretInDb(originalIdp);

                // check if the returned IdP has a redacted relying party secret
                assertRelyingPartySecretIsRedacted(originalIdp);
            }

            @Test
            void shouldReject_IdzAndAliasZidAreEqual_UaaZone() throws Exception {
                shouldReject_IdzAndAliasZidAreEqual(IdentityZone.getUaa());
            }

            @Test
            void shouldReject_IdzAndAliasZidAreEqual_CustomZone() throws Exception {
                shouldReject_IdzAndAliasZidAreEqual(customZone);
            }

            private void shouldReject_IdzAndAliasZidAreEqual(final IdentityZone zone) throws Exception {
                final IdentityProvider<?> idp = buildOidcIdpWithAliasProperties(zone.getId(), null, zone.getId());
                shouldRejectCreation(zone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
            }

            @Test
            void shouldReject_AliasNotSupportedForIdpType_UaaToCustomZone() throws Exception {
                shouldReject_AliasNotSupportedForIdpType(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_AliasNotSupportedForIdpType_CustomToUaaZone() throws Exception {
                shouldReject_AliasNotSupportedForIdpType(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_AliasNotSupportedForIdpType(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
                final IdentityProvider<?> uaaIdp = buildUaaIdpWithAliasProperties(zone1.getId(), null, zone2.getId());
                shouldRejectCreation(zone1, uaaIdp, HttpStatus.UNPROCESSABLE_ENTITY);
            }

            @Test
            void shouldReject_NeitherIdzNorAliasZidIsUaa() throws Exception {
                final IdentityZone otherCustomZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
                final IdentityProvider<?> idp = buildOidcIdpWithAliasProperties(customZone.getId(), null, otherCustomZone.getId());
                shouldRejectCreation(customZone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
            }

            @Test
            void shouldReject_IdzReferencedInAliasZidDoesNotExist() throws Exception {
                final IdentityProvider<?> provider = buildOidcIdpWithAliasProperties(
                        IdentityZone.getUaaZoneId(),
                        null,
                        UUID.randomUUID().toString() // does not exist
                );
                shouldRejectCreation(IdentityZone.getUaa(), provider, HttpStatus.UNPROCESSABLE_ENTITY);
            }

            @Test
            void shouldReject_IdpWithOriginAlreadyExistsInAliasZone_CustomToUaaZone() throws Exception {
                shouldReject_IdpWithOriginAlreadyExistsInAliasZone(customZone, IdentityZone.getUaa());
            }

            @Test
            void shouldReject_IdpWithOriginAlreadyExistsInAliasZone_UaaToCustomZone() throws Exception {
                shouldReject_IdpWithOriginAlreadyExistsInAliasZone(IdentityZone.getUaa(), customZone);
            }

            private void shouldReject_IdpWithOriginAlreadyExistsInAliasZone(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
                // create IdP with origin key in zone 1
                final IdentityProvider<?> createdIdp1 = createIdp(
                        zone1,
                        buildOidcIdpWithAliasProperties(zone1.getId(), null, null)
                );
                assertThat(createdIdp1).isNotNull();

                // then, create an IdP in zone 2 with the same origin key for which an alias in zone 1 should be created -> should fail
                shouldRejectCreation(
                        zone2,
                        buildIdpWithAliasProperties(zone2.getId(), null, zone1.getId(), createdIdp1.getOriginKey(), OIDC10),
                        HttpStatus.CONFLICT
                );
            }
        }

        @Nested
        class AliasFeatureDisabled extends CreateBase {
            protected AliasFeatureDisabled() {
                super(false);
            }

            @Test
            void shouldReject_OnlyAliasZidSet_UaaToCustomZone() throws Exception {
                shouldReject_OnlyAliasZidSet(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_OnlyAliasZidSet_CustomToUaaZone() throws Exception {
                shouldReject_OnlyAliasZidSet(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_OnlyAliasZidSet(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Exception {
                final IdentityProvider<?> idp = buildOidcIdpWithAliasProperties(
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                shouldRejectCreation(zone1, idp, HttpStatus.UNPROCESSABLE_ENTITY);
            }
        }

        private void shouldRejectCreation(final IdentityZone zone, final IdentityProvider<?> idp, final HttpStatus expectedStatus) throws Exception {
            assertThat(expectedStatus.isError()).isTrue();

            final MvcResult result = createIdpAndReturnResult(zone, idp);
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatus.value());

            // after the failed creation, the IdP must not exist
            final List<IdentityProvider<?>> idpsInZoneAfterFailedCreation = readAllIdpsInZone(zone);
            assertThat(idpsInZoneAfterFailedCreation.stream().map(IdentityProvider::getOriginKey).collect(toSet()))
                    .doesNotContain(idp.getOriginKey());
        }
    }

    @Nested
    class Update {
        abstract class UpdateBase {
            protected final boolean aliasFeatureEnabled;

            protected UpdateBase(final boolean aliasFeatureEnabled) {
                this.aliasFeatureEnabled = aliasFeatureEnabled;
            }

            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(aliasFeatureEnabled);
            }

            @Test
            void shouldReject_NoExistingAlias_AliasIdSet_UaaZone() throws Exception {
                shouldReject_NoExistingAlias_AliasIdSet(IdentityZone.getUaa());
            }

            @Test
            void shouldReject_NoExistingAlias_AliasIdSet_CustomZone() throws Exception {
                shouldReject_NoExistingAlias_AliasIdSet(customZone);
            }

            private void shouldReject_NoExistingAlias_AliasIdSet(final IdentityZone zone) throws Exception {
                final IdentityProvider<?> existingIdp = createIdp(
                        zone,
                        buildOidcIdpWithAliasProperties(zone.getId(), null, null)
                );
                assertThat(existingIdp.getAliasZid()).isBlank();
                existingIdp.setAliasId(UUID.randomUUID().toString());
                shouldRejectUpdate(zone, existingIdp, HttpStatus.UNPROCESSABLE_ENTITY);
            }
        }

        @Nested
        class AliasFeatureEnabled extends UpdateBase {
            protected AliasFeatureEnabled() {
                super(true);
            }

            @Nested
            class NoExistingAlias {
                @Test
                void shouldAccept_ShouldCreateNewAlias_UaaToCustomZone() throws Exception {
                    shouldAccept_ShouldCreateNewAlias(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_ShouldCreateNewAlias_CustomToUaaZone() throws Exception {
                    shouldAccept_ShouldCreateNewAlias(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_ShouldCreateNewAlias(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Exception {
                    // create regular idp without alias properties in zone 1
                    final IdentityProvider<?> existingIdpWithoutAlias = createIdp(
                            zone1,
                            buildOidcIdpWithAliasProperties(zone1.getId(), null, null)
                    );
                    assertThat(existingIdpWithoutAlias).isNotNull();
                    assertThat(existingIdpWithoutAlias.getId()).isNotBlank();

                    // perform update: set Alias ZID
                    existingIdpWithoutAlias.setAliasZid(zone2.getId());
                    final IdentityProvider<?> idpAfterUpdate = updateIdp(zone1, existingIdpWithoutAlias);
                    assertThat(idpAfterUpdate.getAliasId()).isNotBlank();
                    assertThat(idpAfterUpdate.getAliasZid()).isNotBlank();
                    assertThat(zone2.getId()).isEqualTo(idpAfterUpdate.getAliasZid());

                    // read alias IdP through alias id in original IdP
                    final String id = idpAfterUpdate.getAliasId();
                    final Optional<IdentityProvider<?>> idp = readIdpFromZoneIfExists(zone2.getId(), id);
                    assertThat(idp).isPresent();
                    final IdentityProvider<?> aliasIdp = idp.get();
                    assertIdpReferencesOtherIdp(aliasIdp, idpAfterUpdate);
                    assertOtherPropertiesAreEqual(idpAfterUpdate, aliasIdp);
                }

                @Test
                void shouldReject_ReferencedZoneDoesNotExist() throws Exception {
                    final IdentityZone zone = IdentityZone.getUaa();
                    final IdentityProvider<?> existingIdp = createIdp(
                            zone,
                            buildUaaIdpWithAliasProperties(zone.getId(), null, null)
                    );

                    existingIdp.setAliasZid(UUID.randomUUID().toString()); // non-existing zone

                    shouldRejectUpdate(zone, existingIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldReject_AliasNotSupportedForIdpType_UaaToCustomZone() throws Exception {
                    shouldReject_AliasNotSupportedForIdpType(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_AliasNotSupportedForIdpType_CustomZone() throws Exception {
                    shouldReject_AliasNotSupportedForIdpType(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_AliasNotSupportedForIdpType(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
                    final IdentityProvider<?> uaaIdp = buildUaaIdpWithAliasProperties(zone1.getId(), null, null);
                    final IdentityProvider<?> createdProvider = createIdp(zone1, uaaIdp);
                    assertThat(createdProvider.getAliasZid()).isBlank();

                    // try to create an alias for the IdP -> should fail because of the IdP's type
                    createdProvider.setAliasZid(zone2.getId());
                    shouldRejectUpdate(zone1, createdProvider, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone_UaaToCustomZone() throws Exception {
                    shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone_CustomToUaaZone() throws Exception {
                    shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
                    // create IdP with origin key in zone 2
                    final IdentityProvider<?> existingIdpInZone2 = buildOidcIdpWithAliasProperties(zone2.getId(), null, null);
                    createIdp(zone2, existingIdpInZone2);

                    // create IdP with same origin key in zone 1
                    final IdentityProvider<?> idp = buildIdpWithAliasProperties(
                            zone1.getId(),
                            null,
                            null,
                            existingIdpInZone2.getOriginKey(), // same origin key
                            OIDC10
                    );
                    final IdentityProvider<?> providerInZone1 = createIdp(zone1, idp);

                    // update the alias ZID to zone 2, where an IdP with this origin already exists -> should fail
                    providerInZone1.setAliasZid(zone2.getId());
                    shouldRejectUpdate(zone1, providerInZone1, HttpStatus.CONFLICT);
                }

                @Test
                void shouldReject_AliasZidSetToSameZone_UaaZone() throws Exception {
                    shouldReject_AliasZidSetToSameZone(IdentityZone.getUaa());
                }

                @Test
                void shouldReject_AliasZidSetToSameZone_CustomZone() throws Exception {
                    shouldReject_AliasZidSetToSameZone(customZone);
                }

                private void shouldReject_AliasZidSetToSameZone(final IdentityZone zone) throws Exception {
                    final IdentityProvider<?> idp = createIdp(
                            zone,
                            buildOidcIdpWithAliasProperties(zone.getId(), null, null)
                    );
                    idp.setAliasZid(zone.getId());
                    shouldRejectUpdate(zone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
                }
            }

            @Nested
            class ExistingAlias {
                @Test
                void shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged_UaaToCustomZone() throws Exception {
                    shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged_CustomToUaaZone() throws Exception {
                    shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
                    // create an IdP with an alias
                    final IdentityProvider<?> originalIdp = createIdpWithAlias(zone1, zone2);

                    // update other property
                    final String newName = "new name";
                    originalIdp.setName(newName);
                    final IdentityProvider<?> updatedOriginalIdp = updateIdp(zone1, originalIdp);
                    assertThat(updatedOriginalIdp).isNotNull();
                    assertThat(updatedOriginalIdp.getAliasId()).isNotBlank();
                    assertThat(updatedOriginalIdp.getAliasZid()).isNotBlank()
                            .isEqualTo(zone2.getId());
                    assertThat(updatedOriginalIdp.getName()).isNotBlank().isEqualTo(newName);

                    // check if the change is propagated to the alias IdP
                    final String id = updatedOriginalIdp.getAliasId();
                    final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), id);
                    assertThat(aliasIdp).isPresent();
                    assertIdpReferencesOtherIdp(aliasIdp.get(), updatedOriginalIdp);
                    assertThat(aliasIdp.get().getName()).isNotBlank().isEqualTo(newName);

                    // check if both have the same non-empty relying party secret in the DB
                    assertIdpAndAliasHaveSameRelyingPartySecretInDb(updatedOriginalIdp);

                    // check if the returned IdP has a redacted relying party secret
                    assertRelyingPartySecretIsRedacted(updatedOriginalIdp);
                }

                @Test
                void shouldReject_AliasIdNotSetInPayload_UaaToCustomZone() throws Exception {
                    shouldReject_AliasIdNotSetInPayload(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_AliasIdNotSetInPayload_CustomToUaaZone() throws Exception {
                    shouldReject_AliasIdNotSetInPayload(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_AliasIdNotSetInPayload(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Exception {
                    final IdentityProvider<?> existingIdp = createIdpWithAlias(zone1, zone2);

                    existingIdp.setAliasId(null);
                    existingIdp.setName("some-new-name");
                    shouldRejectUpdate(zone1, existingIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldAccept_ShouldFixDanglingRefByCreatingNewAlias_UaaToCustomZone() throws Exception {
                    shouldAccept_ShouldFixDanglingRefByCreatingNewAlias(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_ShouldFixDanglingRefByCreatingNewAlias_CustomToUaaZone() throws Exception {
                    shouldAccept_ShouldFixDanglingRefByCreatingNewAlias(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_ShouldFixDanglingRefByCreatingNewAlias(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
                    final IdentityProvider<?> idp = createIdpWithAlias(zone1, zone2);

                    // delete the alias IdP directly in the DB -> after that, there is a dangling reference
                    deleteIdpViaDb(idp.getOriginKey(), zone2.getId());

                    // update some other property on the original IdP
                    idp.setName("some-new-name");
                    final IdentityProvider<?> updatedIdp = updateIdp(zone1, idp);
                    assertThat(updatedIdp.getAliasId()).isNotBlank().isNotEqualTo(idp.getAliasId());
                    assertThat(updatedIdp.getAliasZid()).isNotBlank().isEqualTo(idp.getAliasZid());

                    // check if the new alias IdP is present and has the correct properties
                    final String id = updatedIdp.getAliasId();
                    final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), id);
                    assertThat(aliasIdp).isPresent();
                    assertIdpReferencesOtherIdp(updatedIdp, aliasIdp.get());
                    assertOtherPropertiesAreEqual(updatedIdp, aliasIdp.get());

                    // check if both have the same non-empty relying party secret
                    assertIdpAndAliasHaveSameRelyingPartySecretInDb(updatedIdp);

                    // check if the returned IdP has a redacted relying party secret
                    assertRelyingPartySecretIsRedacted(updatedIdp);
                }

                @ParameterizedTest
                @MethodSource("shouldReject_ChangingAliasPropertiesOfIdpWithAlias")
                void shouldReject_ChangingAliasPropertiesOfIdpWithAlias_UaaToCustomZone(
                        final String newAliasId,
                        final String newAliasZid
                ) throws Throwable {
                    shouldReject_ChangingAliasPropertiesOfIdpWithAlias(newAliasId, newAliasZid, IdentityZone.getUaa(), customZone);
                }

                @ParameterizedTest
                @MethodSource("shouldReject_ChangingAliasPropertiesOfIdpWithAlias")
                void shouldReject_ChangingAliasPropertiesOfIdpWithAlias_CustomToUaaZone(
                        final String newAliasId,
                        final String newAliasZid
                ) throws Throwable {
                    shouldReject_ChangingAliasPropertiesOfIdpWithAlias(newAliasId, newAliasZid, customZone, IdentityZone.getUaa());
                }

                private void shouldReject_ChangingAliasPropertiesOfIdpWithAlias(
                        final String newAliasId,
                        final String newAliasZid,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final IdentityProvider<?> originalIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );
                    originalIdp.setAliasId(newAliasId);
                    originalIdp.setAliasZid(newAliasZid);
                    shouldRejectUpdate(zone1, originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                private static Stream<Arguments> shouldReject_ChangingAliasPropertiesOfIdpWithAlias() {
                    return Stream.of(null, "", "other").flatMap(aliasIdValue ->
                            Stream.of(null, "", "other").map(aliasZidValue ->
                                    Arguments.of(aliasIdValue, aliasZidValue)
                            ));
                }

                @Test
                void shouldReject_CannotFixDanglingRefAsAliasZoneIsNotExisting_UaaToCustomZone() throws Throwable {
                    final IdentityZone zone1 = IdentityZone.getUaa();
                    final IdentityZone zone2 = customZone;

                    final IdentityProvider<?> existingIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );

                    // delete alias IdP
                    deleteIdpViaDb(existingIdp.getOriginKey(), zone2.getId());

                    /* change alias zid to a non-existing zone directly in DB, so that fixing the dangling reference
                     * will fail because the alias zone does not exist */
                    final String nonExistingZoneId = UUID.randomUUID().toString();
                    existingIdp.setAliasZid(nonExistingZoneId);
                    updateIdpViaDb(zone1.getId(), existingIdp);

                    existingIdp.setName("some-new-name");
                    shouldRejectUpdate(zone1, existingIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }
            }

            @Test
            void shouldReject_DanglingRefCannotBeFixedAsOriginAlreadyExistsInAliasZone_UaaToCustomZone() throws Throwable {
                shouldReject_DanglingRefCannotBeFixedAsOriginAlreadyExistsInAliasZone(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_DanglingRefCannotBeFixedAsOriginAlreadyExistsInAliasZone_CustomToUaaZone() throws Throwable {
                shouldReject_DanglingRefCannotBeFixedAsOriginAlreadyExistsInAliasZone(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_DanglingRefCannotBeFixedAsOriginAlreadyExistsInAliasZone(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> existingIdp = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                // delete alias IdP and create a new one in zone 2 without alias but with the same origin
                deleteIdpViaDb(existingIdp.getOriginKey(), zone2.getId());
                final IdentityProvider<?> newIdpWithSameOrigin = buildOidcIdpWithAliasProperties(
                        zone2.getId(),
                        null,
                        null
                );
                newIdpWithSameOrigin.setOriginKey(existingIdp.getOriginKey());
                createIdp(zone2, newIdpWithSameOrigin);

                existingIdp.setAliasId(null);
                existingIdp.setAliasZid(null);
                existingIdp.setName("some-new-name");
                shouldRejectUpdate(zone1, existingIdp, HttpStatus.UNPROCESSABLE_ENTITY);
            }

            @Test
            void shouldReject_IdpInCustomZone_AliasToOtherCustomZone() throws Exception {
                final IdentityProvider<?> idpInCustomZone = createIdp(
                        customZone,
                        buildOidcIdpWithAliasProperties(customZone.getId(), null, null)
                );

                // try to create an alias in another custom zone -> should fail
                idpInCustomZone.setAliasZid("not-uaa");
                shouldRejectUpdate(customZone, idpInCustomZone, HttpStatus.UNPROCESSABLE_ENTITY);
            }
        }

        @Nested
        class AliasFeatureDisabled extends UpdateBase {
            protected AliasFeatureDisabled() {
                super(false);
            }

            @Nested
            class NoExistingAlias {
                @Test
                void shouldReject_AliasZidSet_UaaToCustomZone() throws Throwable {
                    shouldReject_AliasZidSet(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_AliasZidSet_CustomToUaaZone() throws Throwable {
                    shouldReject_AliasZidSet(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_AliasZidSet(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Exception {
                    final IdentityProvider<?> existingIdp = createIdp(
                            zone1,
                            buildOidcIdpWithAliasProperties(zone1.getId(), null, null)
                    );

                    // setting the alias zid should fail
                    existingIdp.setAliasZid(zone2.getId());
                    shouldRejectUpdate(zone1, existingIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }
            }

            /**
             * Test handling of IdPs with an existing alias when the alias feature is now switched off.
             */
            @Nested
            class ExistingAlias {
                @Test
                void shouldReject_OtherPropertiesChangedWhileAliasPropertiesUnchanged_UaaToCustomZone() throws Throwable {
                    shouldReject_OtherPropertiesChangedWhileAliasPropertiesUnchanged(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_OtherPropertiesChangedWhileAliasPropertiesUnchanged_CustomToUaaZone() throws Throwable {
                    shouldReject_OtherPropertiesChangedWhileAliasPropertiesUnchanged(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_OtherPropertiesChangedWhileAliasPropertiesUnchanged(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final IdentityProvider<?> originalIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );

                    // change non-alias property without setting alias properties to null
                    originalIdp.setName("some-new-name");
                    shouldRejectUpdate(zone1, originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldReject_SetOnlyAliasPropertiesToNull_UaaToCustomZone() throws Throwable {
                    shouldReject_SetOnlyAliasPropertiesToNull(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_SetOnlyAliasPropertiesToNull_CustomToUaaZone() throws Throwable {
                    shouldReject_SetOnlyAliasPropertiesToNull(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_SetOnlyAliasPropertiesToNull(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final IdentityProvider<?> originalIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );

                    final String initialAliasId = originalIdp.getAliasId();
                    assertThat(initialAliasId).isNotBlank();
                    final String initialAliasZid = originalIdp.getAliasZid();
                    assertThat(initialAliasZid).isNotBlank();

                    // change non-alias property without setting alias properties to null
                    originalIdp.setAliasId(null);
                    originalIdp.setAliasZid(null);
                    shouldRejectUpdate(zone1, originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldReject_SetAliasPropertiesToNullAndChangeOtherProperties_UaaToCustomZone() throws Throwable {
                    shouldReject_SetAliasPropertiesToNullAndChangeOtherProperties(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_SetAliasPropertiesToNullAndChangeOtherProperties_CustomToUaaZone() throws Throwable {
                    shouldReject_SetAliasPropertiesToNullAndChangeOtherProperties(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_SetAliasPropertiesToNullAndChangeOtherProperties(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final IdentityProvider<?> originalIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );

                    final String initialAliasId = originalIdp.getAliasId();
                    assertThat(initialAliasId).isNotBlank();
                    final String initialAliasZid = originalIdp.getAliasZid();
                    assertThat(initialAliasZid).isNotBlank();
                    final String initialName = originalIdp.getName();
                    assertThat(initialName).isNotBlank();

                    // should reject update
                    originalIdp.setAliasId(null);
                    originalIdp.setAliasZid(null);
                    originalIdp.setName("some-new-name");
                    shouldRejectUpdate(zone1, originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldReject_AliasIdOfExistingIdpMissing_UaaToCustomZone() throws Throwable {
                    shouldReject_AliasIdOfExistingIdpMissing(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_AliasIdOfExistingIdpMissing_CustomToUaaZone() throws Throwable {
                    shouldReject_AliasIdOfExistingIdpMissing(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_AliasIdOfExistingIdpMissing(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final IdentityProvider<?> existingIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );

                    final String initialAliasId = existingIdp.getAliasId();
                    assertThat(initialAliasId).isNotBlank();
                    final String initialName = existingIdp.getName();
                    assertThat(initialName).isNotBlank();

                    // modify existing directly in DB: remove aliasId
                    existingIdp.setAliasId(null);
                    updateIdpViaDb(zone1.getId(), existingIdp);

                    // update original IdP
                    existingIdp.setAliasId(null);
                    existingIdp.setAliasZid(null);
                    existingIdp.setName("some-new-name");
                    shouldRejectUpdate(zone1, existingIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldReject_EvenIfAliasReferenceIsBroken_UaaToCustomZone() throws Throwable {
                    shouldReject_EvenIfAliasReferenceIsBroken(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_EvenIfAliasReferenceIsBroken_CustomToUaaZone() throws Throwable {
                    shouldReject_EvenIfAliasReferenceIsBroken(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_EvenIfAliasReferenceIsBroken(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final IdentityProvider<?> existingIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );

                    // create dangling reference by removing alias IdP directly in DB
                    deleteIdpViaDb(existingIdp.getOriginKey(), zone2.getId());

                    // try to update IdP -> should still fail, even if the alias reference is broken
                    existingIdp.setName("some-new-name");
                    shouldRejectUpdate(zone1, existingIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldReject_OnlyAliasIdSetToNull_UaaToCustomZone() throws Throwable {
                    shouldReject_OnlyAliasIdSetToNull(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_OnlyAliasIdSetToNull_CustomToUaaZone() throws Throwable {
                    shouldReject_OnlyAliasIdSetToNull(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_OnlyAliasIdSetToNull(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final IdentityProvider<?> originalIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );

                    assertThat(originalIdp.getAliasId()).isNotBlank();
                    assertThat(originalIdp.getAliasZid()).isNotBlank();

                    originalIdp.setAliasId(null);
                    shouldRejectUpdate(zone1, originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }

                @Test
                void shouldReject_OnlyAliasZidSetToNull_UaaToCustomZone() throws Throwable {
                    shouldReject_OnlyAliasZidSetToNull(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_OnlyAliasZidSetToNull_CustomToUaaZone() throws Throwable {
                    shouldReject_OnlyAliasZidSetToNull(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_OnlyAliasZidSetToNull(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final IdentityProvider<?> originalIdp = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAlias(zone1, zone2)
                    );

                    assertThat(originalIdp.getAliasId()).isNotBlank();
                    assertThat(originalIdp.getAliasZid()).isNotBlank();

                    originalIdp.setAliasZid(null);
                    shouldRejectUpdate(zone1, originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
                }
            }
        }

        private IdentityProvider<?> updateIdp(final IdentityZone zone, final IdentityProvider<?> updatePayload) throws Exception {
            updatePayload.setIdentityZoneId(zone.getId());
            final MvcResult result = updateIdpAndReturnResult(zone, updatePayload);
            assertThat(result.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());

            final IdentityProvider<?> originalIdpAfterUpdate = JsonUtils.readValue(
                    result.getResponse().getContentAsString(),
                    IdentityProvider.class
            );
            assertThat(originalIdpAfterUpdate).isNotNull();
            assertThat(originalIdpAfterUpdate.getIdentityZoneId()).isNotBlank()
                    .isEqualTo(zone.getId());
            return originalIdpAfterUpdate;
        }

        private MvcResult updateIdpAndReturnResult(final IdentityZone zone, final IdentityProvider<?> updatePayload) throws Exception {
            final String id = updatePayload.getId();
            assertThat(id).isNotNull().isNotBlank();

            final MockHttpServletRequestBuilder updateRequestBuilder = put("/identity-providers/" + id)
                    .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getId())
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(updatePayload));
            return mockMvc.perform(updateRequestBuilder).andReturn();
        }

        private void shouldRejectUpdate(final IdentityZone zone, final IdentityProvider<?> idp, final HttpStatus expectedErrorStatus) throws Exception {
            assertThat(idp.getId()).isNotBlank();
            assertThat(expectedErrorStatus.isError()).isTrue();

            // read existing IdP before update
            final String id = idp.getId();
            final Optional<IdentityProvider<?>> idpBeforeUpdateOpt = readIdpFromZoneIfExists(zone.getId(), id);
            assertThat(idpBeforeUpdateOpt).isPresent();
            final IdentityProvider<?> idpBeforeUpdate = idpBeforeUpdateOpt.get();

            // if alias properties set: read alias IdP before update
            final IdentityProvider<?> aliasIdpBeforeUpdate;
            if (hasText(idpBeforeUpdate.getAliasId()) && hasText(idpBeforeUpdate.getAliasZid())) {
                final Optional<IdentityProvider<?>> aliasIdpBeforeUpdateOpt = readIdpFromZoneIfExists(
                        idpBeforeUpdate.getAliasZid(),
                        idpBeforeUpdate.getAliasId()
                );
                aliasIdpBeforeUpdate = aliasIdpBeforeUpdateOpt
                        .orElse(null); // for test cases involving dangling references, the alias might not exist even though one is referenced
            } else {
                aliasIdpBeforeUpdate = null;
            }

            // perform the update -> should fail
            final MvcResult result = updateIdpAndReturnResult(zone, idp);
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedErrorStatus.value());

            // read again: original IdP should remain unchanged
            final Optional<IdentityProvider<?>> idpAfterFailedUpdateOpt = readIdpFromZoneIfExists(
                    zone.getId(),
                    idp.getId()
            );
            assertThat(idpAfterFailedUpdateOpt).contains(idpBeforeUpdate);

            // if an alias IdP was present before update, check if it also remains unchanged
            if (aliasIdpBeforeUpdate != null) {
                final Optional<IdentityProvider<?>> aliasIdpAfterFailedUpdateOpt = readIdpFromZoneIfExists(
                        idpBeforeUpdate.getAliasZid(),
                        idpBeforeUpdate.getAliasId()
                );
                assertThat(aliasIdpAfterFailedUpdateOpt).contains(aliasIdpBeforeUpdate);
            }
        }
    }

    @Nested
    class Delete {
        abstract class DeleteBase {
            protected final boolean aliasFeatureEnabled;

            public DeleteBase(final boolean aliasFeatureEnabled) {
                this.aliasFeatureEnabled = aliasFeatureEnabled;
            }

            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(aliasFeatureEnabled);
            }
        }

        @Nested
        class AliasFeatureEnabled extends DeleteBase {
            public AliasFeatureEnabled() {
                super(true);
            }

            @Test
            void shouldIgnoreDanglingReferenceToAliasIdp_UaaToCustomZone() throws Throwable {
                shouldIgnoreDanglingReferenceToAliasIdp(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldIgnoreDanglingReferenceToAliasIdp_CustomToUaaZone() throws Throwable {
                shouldIgnoreDanglingReferenceToAliasIdp(customZone, IdentityZone.getUaa());
            }

            private void shouldIgnoreDanglingReferenceToAliasIdp(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> originalIdp = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                // create a dangling reference by deleting the alias IdP directly in the DB
                deleteIdpViaDb(originalIdp.getOriginKey(), zone2.getId());

                // delete the original IdP -> dangling reference should be ignored
                final MvcResult deleteResult = deleteIdpAndReturnResult(zone1, originalIdp.getId());
                assertThat(deleteResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());

                // original IdP should no longer exist
                assertIdpDoesNotExist(originalIdp.getId(), zone1.getId());
            }

            @Test
            void deletionWithExistingAliasIdp_UaaToCustomZone() throws Throwable {
                deletionWithExistingAliasIdp(IdentityZone.getUaa(), customZone);
            }

            @Test
            void deletionWithExistingAliasIdp_CustomToUaaZone() throws Throwable {
                deletionWithExistingAliasIdp(customZone, IdentityZone.getUaa());
            }

            private void deletionWithExistingAliasIdp(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                // create IdP in zone 1 with alias in zone 2
                final IdentityProvider<?> idpInZone1 = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );
                final String id = idpInZone1.getId();
                assertThat(id).isNotBlank();
                final String aliasId = idpInZone1.getAliasId();
                assertThat(aliasId).isNotBlank();
                final String aliasZid = idpInZone1.getAliasZid();
                assertThat(aliasZid).isNotBlank().isEqualTo(zone2.getId());

                // check if alias IdP is available in zone 2
                final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), aliasId);
                assertThat(aliasIdp).isPresent();
                assertThat(aliasIdp.get().getAliasId()).isNotBlank().isEqualTo(id);
                assertThat(aliasIdp.get().getAliasZid()).isNotBlank().isEqualTo(idpInZone1.getIdentityZoneId());

                // delete IdP in zone 1
                final MvcResult deleteResult = deleteIdpAndReturnResult(zone1, id);
                assertThat(deleteResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());

                // if the alias feature is enabled, the alias should also be removed
                assertIdpDoesNotExist(aliasId, aliasZid);
            }
        }

        @Nested
        class AliasFeatureDisabled extends DeleteBase {
            public AliasFeatureDisabled() {
                super(false);
            }

            @Test
            void shouldRejectDeletion_WhenAliasIdpExists_UaaToCustomZone() throws Throwable {
                shouldRejectDeletion_WhenAliasIdpExists(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldRejectDeletion_WhenAliasIdpExists_CustomToUaaZone() throws Throwable {
                shouldRejectDeletion_WhenAliasIdpExists(customZone, IdentityZone.getUaa());
            }

            private void shouldRejectDeletion_WhenAliasIdpExists(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                // create IdP in zone 1 with alias in zone 2
                final IdentityProvider<?> idpInZone1 = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );
                final String id = idpInZone1.getId();
                assertThat(id).isNotBlank();
                final String aliasId = idpInZone1.getAliasId();
                assertThat(aliasId).isNotBlank();
                final String aliasZid = idpInZone1.getAliasZid();
                assertThat(aliasZid).isNotBlank().isEqualTo(zone2.getId());

                // check if alias IdP is available in zone 2
                final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), aliasId);
                assertThat(aliasIdp).isPresent();
                assertThat(aliasIdp.get().getAliasId()).isNotBlank().isEqualTo(id);
                assertThat(aliasIdp.get().getAliasZid()).isNotBlank().isEqualTo(idpInZone1.getIdentityZoneId());

                // delete IdP in zone 1 -> should be rejected since alias feature is disabled
                final MvcResult deleteResult = deleteIdpAndReturnResult(zone1, id);
                assertThat(deleteResult.getResponse().getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY.value());
            }
        }

        private MvcResult deleteIdpAndReturnResult(final IdentityZone zone, final String id) throws Exception {
            final String accessTokenForZone1 = getAccessTokenForZone(zone.getId());
            final MockHttpServletRequestBuilder deleteRequestBuilder = delete("/identity-providers/" + id)
                    .header("Authorization", "Bearer " + accessTokenForZone1)
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
            return mockMvc.perform(deleteRequestBuilder).andReturn();
        }

        private void assertIdpDoesNotExist(final String id, final String zoneId) throws Exception {
            final Optional<IdentityProvider<?>> idp = readIdpFromZoneIfExists(zoneId, id);
            assertThat(idp).isNotPresent();
        }
    }

    private static void assertIdpReferencesOtherIdp(final IdentityProvider<?> idp, final IdentityProvider<?> referencedIdp) {
        assertThat(idp).isNotNull();
        assertThat(referencedIdp).isNotNull();
        assertThat(referencedIdp.getId()).isNotBlank().isEqualTo(idp.getAliasId());
        assertThat(referencedIdp.getIdentityZoneId()).isNotBlank().isEqualTo(idp.getAliasZid());
    }

    private static void assertOtherPropertiesAreEqual(final IdentityProvider<?> idp, final IdentityProvider<?> aliasIdp) {
        // the configs should be identical
        final OIDCIdentityProviderDefinition originalIdpConfig = (OIDCIdentityProviderDefinition) idp.getConfig();
        final OIDCIdentityProviderDefinition aliasIdpConfig = (OIDCIdentityProviderDefinition) aliasIdp.getConfig();
        assertThat(aliasIdpConfig).isEqualTo(originalIdpConfig);

        // check if remaining properties are equal
        assertThat(aliasIdp.getOriginKey()).isEqualTo(idp.getOriginKey());
        assertThat(aliasIdp.getName()).isEqualTo(idp.getName());
        assertThat(aliasIdp.getType()).isEqualTo(idp.getType());
        assertThat(aliasIdp.isActive()).isEqualTo(idp.isActive());

        // it is expected that the two entities have differing values for 'lastmodified', 'created' and 'version'
    }

    private IdentityProvider<?> createIdpWithAlias(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
        final IdentityProvider<?> provider = buildOidcIdpWithAliasProperties(zone1.getId(), null, zone2.getId());
        final IdentityProvider<?> createdOriginalIdp = createIdp(zone1, provider);
        assertThat(createdOriginalIdp.getAliasId()).isNotBlank();
        assertThat(createdOriginalIdp.getAliasZid()).isNotBlank();
        return createdOriginalIdp;
    }

    private IdentityProvider<?> createIdp(final IdentityZone zone, final IdentityProvider<?> idp) throws Exception {
        final MvcResult createResult = createIdpAndReturnResult(zone, idp);
        assertThat(createResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return JsonUtils.readValue(createResult.getResponse().getContentAsString(), IdentityProvider.class);
    }

    private MvcResult createIdpAndReturnResult(final IdentityZone zone, final IdentityProvider<?> idp) throws Exception {
        final MockHttpServletRequestBuilder createRequestBuilder = post("/identity-providers")
                .param("rawConfig", "true")
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(idp));
        return mockMvc.perform(createRequestBuilder).andReturn();
    }

    private <T> T executeWithTemporarilyEnabledAliasFeature(
            final boolean aliasFeatureEnabledBeforeAction,
            final ThrowingSupplier<T> action
    ) throws Throwable {
        arrangeAliasFeatureEnabled(true);
        try {
            return action.get();
        } finally {
            arrangeAliasFeatureEnabled(aliasFeatureEnabledBeforeAction);
        }
    }

    private String getAccessTokenForZone(final String zoneId) throws Exception {
        final String cacheLookupResult = accessTokenCache.get(zoneId);
        if (cacheLookupResult != null) {
            return cacheLookupResult;
        }

        final List<String> scopesForZone = getScopesForZone(zoneId, "admin");

        final ScimUser adminUser = MockMvcUtils.createAdminForZone(
                mockMvc,
                adminToken,
                String.join(",", scopesForZone),
                IdentityZone.getUaaZoneId()
        );
        final String accessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(
                mockMvc,
                "identity",
                "identitysecret",
                adminUser.getId(),
                adminUser.getUserName(),
                adminUser.getPassword(),
                String.join(" ", scopesForZone),
                TokenConstants.TokenFormat.JWT // use JWT for later checking if all scopes are present
        );

        // check if the token contains the expected scopes
        final Claims claims = UaaTokenUtils.getClaimsFromTokenString(accessToken);
        assertThat(claims.getScope()).hasSameElementsAs(scopesForZone);

        // cache the access token
        accessTokenCache.put(zoneId, accessToken);

        return accessToken;
    }

    private Optional<IdentityProvider<?>> readIdpFromZoneIfExists(final String zoneId, final String id) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/identity-providers/" + id)
                .param("rawConfig", "true")
                .header(IdentityZoneSwitchingFilter.HEADER, zoneId)
                .header("Authorization", "Bearer " + getAccessTokenForZone(zoneId));
        final MvcResult getResult = mockMvc.perform(getRequestBuilder).andReturn();
        final int responseStatus = getResult.getResponse().getStatus();
        assertThat(responseStatus).isIn(404, 200);

        return switch (responseStatus) {
            case 404 -> Optional.empty();
            case 200 -> {
                final IdentityProvider<?> responseBody = JsonUtils.readValue(
                        getResult.getResponse().getContentAsString(),
                        IdentityProvider.class
                );
                yield Optional.ofNullable(responseBody);
            }
            default ->
                // should not happen
                    Optional.empty();
        };
    }

    private List<IdentityProvider<?>> readAllIdpsInZone(final IdentityZone zone) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/identity-providers")
                .param("rawConfig", "true")
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()));
        final MvcResult getResult = mockMvc.perform(getRequestBuilder).andExpect(status().isOk()).andReturn();
        return JsonUtils.readValue(getResult.getResponse().getContentAsString(), new TypeReference<>() {
        });
    }

    private void deleteIdpViaDb(final String originKey, final String zoneId) {
        final JdbcIdentityProviderProvisioning identityProviderProvisioning = webApplicationContext
                .getBean(JdbcIdentityProviderProvisioning.class);
        final int rowsDeleted = identityProviderProvisioning.deleteByOrigin(originKey, zoneId);
        assertThat(rowsDeleted).isOne();
    }

    private void assertIdpAndAliasHaveSameRelyingPartySecretInDb(final IdentityProvider<?> originalIdp) {
        assertThat(originalIdp.getType()).isEqualTo(OIDC10);
        assertThat(originalIdp.getAliasId()).isNotNull().isNotBlank();
        assertThat(originalIdp.getAliasZid()).isNotNull().isNotBlank();

        final Optional<String> relyingPartySecretOriginalIdpOpt = readIdpViaDb(originalIdp.getId(), originalIdp.getIdentityZoneId())
                .map(IdentityProvider::getConfig)
                .map(it -> (AbstractExternalOAuthIdentityProviderDefinition<?>) it)
                .map(AbstractExternalOAuthIdentityProviderDefinition::getRelyingPartySecret);
        assertThat(relyingPartySecretOriginalIdpOpt).isPresent();
        final String relyingPartySecretOriginalIdp = relyingPartySecretOriginalIdpOpt.get();
        assertThat(relyingPartySecretOriginalIdp).isNotBlank();

        final Optional<String> relyingPartySecretAliasIdpOpt = readIdpViaDb(originalIdp.getAliasId(), originalIdp.getAliasZid())
                .map(IdentityProvider::getConfig)
                .map(it -> (AbstractExternalOAuthIdentityProviderDefinition<?>) it)
                .map(AbstractExternalOAuthIdentityProviderDefinition::getRelyingPartySecret);
        assertThat(relyingPartySecretAliasIdpOpt).isPresent();
        final String relyingPartySecretAliasIdp = relyingPartySecretAliasIdpOpt.get();
        assertThat(relyingPartySecretAliasIdp).isNotBlank();

        assertThat(relyingPartySecretOriginalIdp).isEqualTo(relyingPartySecretAliasIdp);
    }

    private Optional<IdentityProvider<?>> readIdpViaDb(final String id, final String zoneId) {
        final JdbcIdentityProviderProvisioning identityProviderProvisioning = webApplicationContext
                .getBean(JdbcIdentityProviderProvisioning.class);
        final IdentityProvider<?> idp;
        try {
            idp = identityProviderProvisioning.retrieve(id, zoneId);
        } catch (final Exception e) {
            return Optional.empty();
        }
        return Optional.of(idp);
    }

    private IdentityProvider<?> updateIdpViaDb(final String zoneId, final IdentityProvider<?> idp) {
        final JdbcIdentityProviderProvisioning identityProviderProvisioning = webApplicationContext
                .getBean(JdbcIdentityProviderProvisioning.class);
        return identityProviderProvisioning.update(idp, zoneId);
    }

    private static void assertRelyingPartySecretIsRedacted(final IdentityProvider<?> identityProvider) {
        assertThat(identityProvider.getType()).isEqualTo(OIDC10);
        final Optional<AbstractExternalOAuthIdentityProviderDefinition<?>> config = Optional.ofNullable(identityProvider.getConfig())
                .map(it -> (AbstractExternalOAuthIdentityProviderDefinition<?>) it);
        assertThat(config).isPresent();
        assertThat(config.get().getRelyingPartySecret()).isBlank();
    }

    private static List<String> getScopesForZone(final String zoneId, final String... scopes) {
        return Stream.of(scopes).map(scope -> "zones.%s.%s".formatted(zoneId, scope)).toList();
    }

    private static IdentityProvider<?> buildOidcIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid
    ) {
        final String originKey = RANDOM_STRING_GENERATOR.generate();
        return buildIdpWithAliasProperties(idzId, aliasId, aliasZid, originKey, OIDC10);
    }

    private static IdentityProvider<?> buildUaaIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid
    ) {
        final String originKey = RANDOM_STRING_GENERATOR.generate();
        return buildIdpWithAliasProperties(idzId, aliasId, aliasZid, originKey, UAA);
    }

    private void arrangeAliasFeatureEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(idpEntityAliasHandler, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(identityProviderEndpoints, "aliasEntitiesEnabled", enabled);
    }

    private static IdentityProvider<?> buildIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid,
            final String originKey,
            final String type
    ) {
        final AbstractIdentityProviderDefinition definition = buildIdpDefinition(type);

        final IdentityProvider<AbstractIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(idzId);
        provider.setAliasId(aliasId);
        provider.setAliasZid(aliasZid);
        provider.setName(originKey);
        provider.setOriginKey(originKey);
        provider.setType(type);
        provider.setConfig(definition);
        provider.setActive(true);
        return provider;
    }

    private static AbstractIdentityProviderDefinition buildIdpDefinition(final String type) {
        switch (type) {
            case OIDC10:
                final OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
                definition.setAuthMethod(ClientAuthentication.CLIENT_SECRET_BASIC);
                try {
                    return definition
                            .setAuthUrl(URI.create("https://www.example.com/oauth/authorize").toURL())
                            .setLinkText("link text")
                            .setRelyingPartyId("relying-party-id")
                            .setRelyingPartySecret("relying-party-secret")
                            .setShowLinkText(true)
                            .setSkipSslValidation(true)
                            .setTokenKey("key")
                            .setTokenKeyUrl(URI.create("https://www.example.com/token_keys").toURL())
                            .setTokenUrl(URI.create("https://wwww.example.com/oauth/token").toURL());
                } catch (final MalformedURLException e) {
                    throw new RuntimeException(e);
                }
            case UAA:
                final PasswordPolicy passwordPolicy = new PasswordPolicy();
                passwordPolicy.setExpirePasswordInMonths(1);
                passwordPolicy.setMaxLength(100);
                passwordPolicy.setMinLength(10);
                passwordPolicy.setRequireDigit(1);
                passwordPolicy.setRequireUpperCaseCharacter(1);
                passwordPolicy.setRequireLowerCaseCharacter(1);
                passwordPolicy.setRequireSpecialCharacter(1);
                passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
                return new UaaIdentityProviderDefinition(passwordPolicy, null);
            default:
                throw new IllegalArgumentException("IdP type not supported.");
        }
    }
}
