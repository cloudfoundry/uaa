package org.cloudfoundry.identity.uaa.scim.endpoints;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.alias.AliasMockMvcTestBase;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderEndpoints;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.core.type.TypeReference;

@DefaultTestContext
public class ScimUserEndpointsAliasMockMvcTests extends AliasMockMvcTestBase {
    private IdentityProviderAliasHandler idpEntityAliasHandler;
    private IdentityProviderEndpoints identityProviderEndpoints;
    private ScimUserAliasHandler scimUserAliasHandler;

    @BeforeEach
    void setUp() throws Exception {
        setUpTokensAndCustomZone();

        idpEntityAliasHandler = requireNonNull(webApplicationContext.getBean(IdentityProviderAliasHandler.class));
        identityProviderEndpoints = requireNonNull(webApplicationContext.getBean(IdentityProviderEndpoints.class));
        scimUserAliasHandler = requireNonNull(webApplicationContext.getBean(ScimUserAliasHandler.class));
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
            void shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand_UaaToCustomZone() throws Throwable {
                shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand_CustomToUaaZone() throws Throwable {
                shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand(customZone, IdentityZone.getUaa());
            }

            private void shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        false,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                // create a user with an alias in zone 1
                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                final ScimUser createdUserWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        false,
                        () -> createScimUser(zone1, scimUser)
                );
                assertThat(createdUserWithAlias.getAliasId()).isNotBlank();
                assertThat(createdUserWithAlias.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());

                // read all users in zone 1 and search for created user
                final List<ScimUser> allUsersInZone1 = readRecentlyCreatedUsersInZone(zone1);
                final Optional<ScimUser> createdUserOpt = allUsersInZone1.stream()
                        .filter(user -> user.getUserName().equals(createdUserWithAlias.getUserName()))
                        .findFirst();
                assertThat(createdUserOpt).isPresent();

                // check if the user has non-empty alias properties
                final ScimUser createdUser = createdUserOpt.get();
                assertThat(createdUser).isEqualTo(createdUserWithAlias);
                assertThat(createdUser.getAliasId()).isNotBlank().isEqualTo(createdUserWithAlias.getAliasId());
                assertThat(createdUser.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());
            }
        }
    }

    @Nested
    class Create {
        abstract class CreateBase {
            protected final boolean aliasFeatureEnabled;

            protected CreateBase(final boolean aliasFeatureEnabled) {
                this.aliasFeatureEnabled = aliasFeatureEnabled;
            }

            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(aliasFeatureEnabled);
            }

            @AfterEach
            void tearDown() {
                arrangeAliasFeatureEnabled(true);
            }

            @Test
            final void shouldAccept_AliasPropertiesNotSet_UaaToCustomZone() throws Throwable {
                shouldAccept_AliasPropertiesNotSet(IdentityZone.getUaa(), customZone);
            }

            @Test
            final void shouldAccept_AliasPropertiesNotSet_CustomToUaaZone() throws Throwable {
                shouldAccept_AliasPropertiesNotSet(customZone, IdentityZone.getUaa());
            }

            private void shouldAccept_AliasPropertiesNotSet(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                // create a user with the IdP as its origin but without an alias itself
                final ScimUser scimUserWithoutAlias = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        null
                );
                final ScimUser createdScimUserWithoutAlias = createScimUser(zone1, scimUserWithoutAlias);
                assertThat(createdScimUserWithoutAlias.getAliasId()).isBlank();
                assertThat(createdScimUserWithoutAlias.getAliasZid()).isBlank();
            }

            @Test
            final void shouldReject_AliasIdSet_UaaToCustomZone() throws Throwable {
                shouldReject_AliasIdSet(IdentityZone.getUaa(), customZone);
            }

            @Test
            final void shouldReject_AliasIdSet_CustomToUaaZone() throws Throwable {
                shouldReject_AliasIdSet(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_AliasIdSet(final IdentityZone zone1, final IdentityZone zone2) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        UUID.randomUUID().toString(),
                        null
                );
                shouldRejectCreation(zone1, scimUser, HttpStatus.BAD_REQUEST);
            }
        }

        @Nested
        class AliasFeatureEnabled extends CreateBase {
            protected AliasFeatureEnabled() {
                super(true);
            }

            @Test
            void shouldAccept_ShouldCreateAliasUser_UaaToCustomZone() throws Throwable {
                shouldAccept_ShouldCreateAliasUser(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldAccept_ShouldCreateAliasUser_CustomToUaaZone() throws Throwable {
                shouldAccept_ShouldCreateAliasUser(customZone, IdentityZone.getUaa());
            }

            private void shouldAccept_ShouldCreateAliasUser(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                final ScimUser createdScimUser = createScimUser(zone1, scimUser);
                assertThat(createdScimUser.getAliasId()).isNotBlank();
                assertThat(createdScimUser.getAliasZid()).isNotBlank();

                final List<ScimUser> usersZone2 = readRecentlyCreatedUsersInZone(zone2);
                final Optional<ScimUser> aliasUserOpt = usersZone2.stream()
                        .filter(user -> user.getId().equals(createdScimUser.getAliasId()))
                        .findFirst();
                assertThat(aliasUserOpt).isPresent();
                final ScimUser aliasUser = aliasUserOpt.get();
                assertThat(aliasUser.getAliasId()).isNotBlank().isEqualTo(createdScimUser.getId());
                assertThat(aliasUser.getAliasZid()).isNotBlank().isEqualTo(createdScimUser.getZoneId());
            }

            @Test
            void shouldReject_UserAlreadyExistsInOtherZone_UaaToCustomZone() throws Throwable {
                shouldReject_UserAlreadyExistsInOtherZone(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_UserAlreadyExistsInOtherZone_CustomToUaaZone() throws Throwable {
                shouldReject_UserAlreadyExistsInOtherZone(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_UserAlreadyExistsInOtherZone(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                // create user in zone 2
                final ScimUser existingScimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone2.getId(),
                        null,
                        null
                );
                final ScimUser createdScimUser = createScimUser(zone2, existingScimUser);

                // try to create similar user in zone 1 with aliasZid set to zone 2
                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                assertThat(createdScimUser.getUserName()).isEqualTo(scimUser.getUserName());
                shouldRejectCreation(zone1, scimUser, HttpStatus.CONFLICT);
            }

            @Test
            void shouldReject_IdzIdAndAliasZidAreEqual_UaaZone() throws Throwable {
                shouldReject_IdzIdAndAliasZidAreEqual(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_IdzIdAndAliasZidAreEqual_CustomZone() throws Throwable {
                shouldReject_IdzIdAndAliasZidAreEqual(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_IdzIdAndAliasZidAreEqual(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone1.getId()
                );
                shouldRejectCreation(zone1, scimUser, HttpStatus.BAD_REQUEST);
            }

            @Test
            void shouldReject_NeitherIdzIdNorAliasZidIsUaa() throws Throwable {
                final IdentityZone otherCustomZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        // similar to users, IdPs also cannot be created from one custom IdZ to another custom one
                        () -> createIdpWithAlias(customZone, IdentityZone.getUaa())
                );

                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        customZone.getId(),
                        null,
                        otherCustomZone.getId()
                );
                shouldRejectCreation(customZone, scimUser, HttpStatus.BAD_REQUEST);
            }

            @Test
            void shouldReject_IdzReferencedInAliasZidDoesNotExist() throws Throwable {
                final IdentityZone zone1 = IdentityZone.getUaa();
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, customZone)
                );

                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        UUID.randomUUID().toString() // no zone with this ID will exist
                );
                shouldRejectCreation(zone1, scimUser, HttpStatus.BAD_REQUEST);
            }

            @Test
            void shouldReject_OriginIdpHasNoAlias_UaaToCustomZone() throws Throwable {
                shouldReject_OriginIdpHasNoAlias(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_OriginIdpHasNoAlias_CustomToUaaZone() throws Throwable {
                shouldReject_OriginIdpHasNoAlias(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_OriginIdpHasNoAlias(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithoutAlias = buildIdpWithAliasProperties(
                        zone1.getId(),
                        null,
                        null,
                        RANDOM_STRING_GENERATOR.generate(),
                        OIDC10
                );
                final IdentityProvider<?> createdIdpWithoutAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdp(zone1, idpWithoutAlias)
                );

                final ScimUser userWithAlias = buildScimUser(
                        createdIdpWithoutAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                shouldRejectCreation(zone1, userWithAlias, HttpStatus.BAD_REQUEST);
            }

            @Test
            void shouldReject_OriginIdpHasAliasInDifferentZone_UaaToCustomZone() throws Throwable {
                shouldReject_OriginIdpHasAliasInDifferentZone(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_OriginIdpHasAliasInDifferentZone_CustomToUaaZone() throws Throwable {
                shouldReject_OriginIdpHasAliasInDifferentZone(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_OriginIdpHasAliasInDifferentZone(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> createdIdpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final IdentityZone otherCustomZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

                final ScimUser userWithAlias = buildScimUser(
                        createdIdpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        otherCustomZone.getId()
                );
                shouldRejectCreation(zone1, userWithAlias, HttpStatus.BAD_REQUEST);
            }
        }

        @Nested
        class AliasFeatureDisabled extends CreateBase {
            protected AliasFeatureDisabled() {
                super(false);
            }

            @Test
            void shouldReject_OnlyAliasZidSet_UaaToCustomZone() throws Throwable {
                shouldReject_OnlyAliasZidSet(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldReject_OnlyAliasZidSet_CustomToUaaZone() throws Throwable {
                shouldReject_OnlyAliasZidSet(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_OnlyAliasZidSet(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final ScimUser scimUser = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                shouldRejectCreation(zone1, scimUser, HttpStatus.BAD_REQUEST);
            }
        }

        private void shouldRejectCreation(
                final IdentityZone zone,
                final ScimUser scimUser,
                final HttpStatus expectedStatus
        ) throws Exception {
            final MvcResult result = createScimUserAndReturnResult(zone, scimUser);
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatus.value());
        }
    }

    private static ScimUser buildScimUser(
            final String origin,
            final String zoneId,
            final String aliasId,
            final String aliasZid
    ) {
        final ScimUser scimUser = new ScimUser();
        scimUser.setOrigin(origin);
        scimUser.setAliasId(aliasId);
        scimUser.setAliasZid(aliasZid);
        scimUser.setZoneId(zoneId);

        scimUser.setUserName("john.doe");
        scimUser.setName(new ScimUser.Name("John", "Doe"));
        scimUser.setPrimaryEmail("john.doe@example.com");
        scimUser.setPassword("some-password");

        return scimUser;
    }

    /**
     * Create an SCIM user in the given zone and assert that the operation is successful.
     */
    private ScimUser createScimUser(final IdentityZone zone, final ScimUser scimUser) throws Exception {
        final MvcResult createResult = createScimUserAndReturnResult(zone, scimUser);
        assertThat(createResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        final ScimUser createdScimUser = JsonUtils.readValue(
                createResult.getResponse().getContentAsString(),
                ScimUser.class
        );
        assertThat(createdScimUser).isNotNull();
        assertThat(createdScimUser.getPassword()).isBlank(); // the password should never be returned
        return createdScimUser;
    }

    private MvcResult createScimUserAndReturnResult(
            final IdentityZone zone,
            final ScimUser scimUser
    ) throws Exception {
        final MockHttpServletRequestBuilder createRequestBuilder = post("/Users")
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getSubdomain())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(scimUser));
        return mockMvc.perform(createRequestBuilder).andReturn();
    }

    private List<ScimUser> readRecentlyCreatedUsersInZone(final IdentityZone zone) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/Users")
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                // return most recent users in first page to avoid querying for further pages
                .param("sortBy", "created")
                .param("sortOrder", "descending");
        final MvcResult getResult = mockMvc.perform(getRequestBuilder).andExpect(status().isOk()).andReturn();
        final SearchResults<ScimUser> searchResults = JsonUtils.readValue(
                getResult.getResponse().getContentAsString(),
                new TypeReference<>() {
                }
        );
        assertThat(searchResults).isNotNull();
        return searchResults.getResources();
    }

    @Override
    protected void arrangeAliasFeatureEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(idpEntityAliasHandler, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(identityProviderEndpoints, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(scimUserAliasHandler, "aliasEntitiesEnabled", enabled);
    }
}
