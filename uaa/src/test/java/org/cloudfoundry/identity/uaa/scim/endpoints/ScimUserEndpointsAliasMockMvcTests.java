package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.HttpMethodEnum;
import org.cloudfoundry.identity.uaa.alias.AliasMockMvcTestBase;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderAliasHandler;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderEndpoints;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.services.ScimUserService;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.scim.ScimUser.Group.Type.DIRECT;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class ScimUserEndpointsAliasMockMvcTests extends AliasMockMvcTestBase {

    // There is a race conditions where multiple users with the same name are created between tests
    // We ensure that the tests are independent by having a custom username per test, that we clean
    // up after every test.
    private String TEST_USERNAME;

    private IdentityProviderAliasHandler idpEntityAliasHandler;
    private IdentityProviderEndpoints identityProviderEndpoints;
    private ScimUserAliasHandler scimUserAliasHandler;
    private ScimUserEndpoints scimUserEndpoints;
    private ScimUserService scimUserService;
    @Autowired
    JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() throws Exception {
        TEST_USERNAME = new AlphanumericRandomValueStringGenerator(12).generate().toLowerCase();
        setUpTokensAndCustomZone();

        idpEntityAliasHandler = requireNonNull(webApplicationContext.getBean(IdentityProviderAliasHandler.class));
        identityProviderEndpoints = requireNonNull(webApplicationContext.getBean(IdentityProviderEndpoints.class));
        scimUserAliasHandler = requireNonNull(webApplicationContext.getBean(ScimUserAliasHandler.class));
        scimUserEndpoints = requireNonNull(webApplicationContext.getBean(ScimUserEndpoints.class));
        scimUserService = requireNonNull(webApplicationContext.getBean(ScimUserService.class));
    }

    @AfterEach
    void tearDown() {
        // Delete any test user that was created. Not strictly necessary, but it makes
        // it easier to debug issues by having less users in the database.
        jdbcTemplate.execute("DELETE FROM users WHERE username = '" + TEST_USERNAME + "'");
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
                shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand(uaaZone, customZone);
            }

            @Test
            void shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand_CustomToUaaZone() throws Throwable {
                shouldStillReturnAliasPropertiesOfUsersWithAliasCreatedBeforehand(customZone, uaaZone);
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
                final Optional<ScimUser> createdUserOpt = readUserFromZoneByUsername(scimUser.getUserName(), zone1);
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
                shouldAccept_AliasPropertiesNotSet(uaaZone, customZone);
            }

            @Test
            final void shouldAccept_AliasPropertiesNotSet_CustomToUaaZone() throws Throwable {
                shouldAccept_AliasPropertiesNotSet(customZone, uaaZone);
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
                shouldReject_AliasIdSet(uaaZone, customZone);
            }

            @Test
            final void shouldReject_AliasIdSet_CustomToUaaZone() throws Throwable {
                shouldReject_AliasIdSet(customZone, uaaZone);
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
                shouldAccept_ShouldCreateAliasUser(uaaZone, customZone);
            }

            @Test
            void shouldAccept_ShouldCreateAliasUser_CustomToUaaZone() throws Throwable {
                shouldAccept_ShouldCreateAliasUser(customZone, uaaZone);
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

                // find alias user
                final Optional<ScimUser> aliasUserOpt = readUserFromZoneByUsername(scimUser.getUserName(), zone2);
                assertIsCorrectAliasPair(createdScimUser, aliasUserOpt.get(), zone2);
            }

            @Test
            void shouldReject_UserAlreadyExistsInOtherZone_UaaToCustomZone() throws Throwable {
                shouldReject_UserAlreadyExistsInOtherZone(uaaZone, customZone);
            }

            @Test
            void shouldReject_UserAlreadyExistsInOtherZone_CustomToUaaZone() throws Throwable {
                shouldReject_UserAlreadyExistsInOtherZone(customZone, uaaZone);
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
                shouldReject_IdzIdAndAliasZidAreEqual(uaaZone, customZone);
            }

            @Test
            void shouldReject_IdzIdAndAliasZidAreEqual_CustomZone() throws Throwable {
                shouldReject_IdzIdAndAliasZidAreEqual(customZone, uaaZone);
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
                        () -> createIdpWithAlias(customZone, uaaZone)
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
                final IdentityZone zone1 = uaaZone;
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
                shouldReject_OriginIdpHasNoAlias(uaaZone, customZone);
            }

            @Test
            void shouldReject_OriginIdpHasNoAlias_CustomToUaaZone() throws Throwable {
                shouldReject_OriginIdpHasNoAlias(customZone, uaaZone);
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
                shouldReject_OriginIdpHasAliasInDifferentZone(uaaZone, customZone);
            }

            @Test
            void shouldReject_OriginIdpHasAliasInDifferentZone_CustomToUaaZone() throws Throwable {
                shouldReject_OriginIdpHasAliasInDifferentZone(customZone, uaaZone);
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
                shouldReject_OnlyAliasZidSet(uaaZone, customZone);
            }

            @Test
            void shouldReject_OnlyAliasZidSet_CustomToUaaZone() throws Throwable {
                shouldReject_OnlyAliasZidSet(customZone, uaaZone);
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

            @AfterEach
            void tearDown() {
                arrangeAliasFeatureEnabled(true);
            }

            @ParameterizedTest
            @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
            final void shouldReject_NoExistingAlias_AliasIdSet_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                shouldReject_NoExistingAlias_AliasIdSet(method, uaaZone, customZone);
            }

            @ParameterizedTest
            @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
            final void shouldReject_NoExistingAlias_AliasIdSet_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                shouldReject_NoExistingAlias_AliasIdSet(method, customZone, uaaZone);
            }

            private void shouldReject_NoExistingAlias_AliasIdSet(
                    final HttpMethodEnum method,
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
                        null
                );
                final ScimUser createdScimUser = createScimUser(zone1, scimUser);

                createdScimUser.setAliasId(UUID.randomUUID().toString());
                shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
            }
        }

        @Nested
        class AliasFeatureEnabled extends UpdateBase {
            public AliasFeatureEnabled() {
                super(true);
            }

            @Nested
            class ExistingAlias {
                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser(method, customZone, uaaZone);
                }

                private void shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    final String newUserName = "some-new-username";
                    createdScimUser.setUserName(newUserName);
                    final ScimUser updatedScimUser = updateUser(method, zone1, createdScimUser);
                    assertThat(updatedScimUser.getUserName()).isEqualTo(newUserName);

                    final Optional<ScimUser> aliasUserOpt = readUserFromZoneIfExists(
                            createdScimUser.getAliasId(),
                            zone2.getId()
                    );
                    assertThat(aliasUserOpt).isPresent();

                    assertIsCorrectAliasPair(updatedScimUser, aliasUserOpt.get(), zone2);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldAccept_ShouldFixDanglingReference_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldAccept_ShouldFixDanglingReference(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldAccept_ShouldFixDanglingReference_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldAccept_ShouldFixDanglingReference(method, customZone, uaaZone);
                }

                private void shouldAccept_ShouldFixDanglingReference(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );
                    final String initialAliasId = createdScimUser.getAliasId();
                    assertThat(initialAliasId).isNotBlank();

                    // create dangling reference by deleting alias user
                    deleteUserViaDb(initialAliasId, zone2.getId());

                    // update the original user
                    final String newUserName = "some-new-username";
                    createdScimUser.setUserName(newUserName);
                    final ScimUser updatedScimUser = updateUser(method, zone1, createdScimUser);
                    assertThat(updatedScimUser.getUserName()).isEqualTo(newUserName);

                    // the dangling reference should be fixed
                    final String newAliasId = updatedScimUser.getAliasId();
                    assertThat(newAliasId).isNotBlank().isNotEqualTo(initialAliasId);
                    final Optional<ScimUser> newAliasUserOpt = readUserFromZoneIfExists(
                            newAliasId,
                            zone2.getId()
                    );
                    assertThat(newAliasUserOpt).isPresent();
                    assertIsCorrectAliasPair(updatedScimUser, newAliasUserOpt.get(), zone2);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone(method, customZone, uaaZone);
                }

                private void shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    // create dangling reference by deleting the alias user directly via DB
                    final String aliasId = createdScimUser.getAliasId();
                    assertThat(aliasId).isNotBlank();
                    deleteUserViaDb(aliasId, zone2.getId());

                    // create a new user without alias in the alias zone that has the same username as the original user
                    final ScimUser conflictingUser = buildScimUser(
                            createdScimUser.getOrigin(),
                            zone2.getId(),
                            null,
                            null
                    );
                    createScimUser(zone2, conflictingUser);

                    // update the original user - fixing the dangling ref. not possible since conflicting user exists
                    createdScimUser.setNickName("some-new-nickname");
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.CONFLICT);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasIdSetInExistingButAliasZidNot_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_AliasIdSetInExistingButAliasZidNot(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasIdSetInExistingButAliasZidNot_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_AliasIdSetInExistingButAliasZidNot(method, customZone, uaaZone);
                }

                private void shouldReject_AliasIdSetInExistingButAliasZidNot(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );
                    final String initialAliasId = createdScimUser.getAliasId();
                    assertThat(initialAliasId).isNotBlank();

                    // remove 'aliasId' directly in DB
                    createdScimUser.setAliasId(null);
                    updateUserViaDb(createdScimUser, zone1.getId());

                    // otherwise valid update should now fail
                    createdScimUser.setAliasId(initialAliasId);
                    createdScimUser.setUserName("some-new-username");
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.INTERNAL_SERVER_ERROR);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasPropertiesChanged_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_AliasPropertiesChanged(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasPropertiesChanged_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_AliasPropertiesChanged(method, customZone, uaaZone);
                }

                private void shouldReject_AliasPropertiesChanged(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasZid(UaaStringUtils.EMPTY_STRING);
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_DanglingReferenceAndZoneNotExisting_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_DanglingReferenceAndZoneNotExisting(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_DanglingReferenceAndZoneNotExisting_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_DanglingReferenceAndZoneNotExisting(method, customZone, uaaZone);
                }

                private void shouldReject_DanglingReferenceAndZoneNotExisting(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    // create a dangling reference by changing the alias zone to a non-existing one
                    createdScimUser.setAliasZid(UUID.randomUUID().toString());
                    final ScimUser userWithDanglingRef = updateUserViaDb(createdScimUser, zone1.getId());

                    // updating the user should fail - the dangling reference cannot be fixed
                    userWithDanglingRef.setUserName("some-new-username");
                    shouldRejectUpdate(method, zone1, userWithDanglingRef, HttpStatus.UNPROCESSABLE_ENTITY);
                }
            }

            @Nested
            class NoExistingAlias {
                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet(method, customZone, uaaZone);
                }

                private void shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasZid(zone2.getId());
                    final ScimUser updatedScimUser = updateUser(method, zone1, createdScimUser);
                    assertThat(updatedScimUser.getAliasId()).isNotBlank();
                    assertThat(updatedScimUser.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());

                    final Optional<ScimUser> aliasUserOpt = readUserFromZoneIfExists(
                            updatedScimUser.getAliasId(),
                            updatedScimUser.getAliasZid()
                    );
                    assertThat(aliasUserOpt).isPresent();
                    final ScimUser aliasUser = aliasUserOpt.get();
                    assertIsCorrectAliasPair(updatedScimUser, aliasUser, zone2);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void versionHandlingUaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    testVersionHandling(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void versionHandlingCustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    testVersionHandling(method, customZone, uaaZone);
                }

                private void testVersionHandling(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );
                    assertThat(createdScimUser.getVersion()).isZero();

                    createdScimUser.setAliasZid(zone2.getId());
                    final ScimUser updatedScimUser = updateUser(method, zone1, createdScimUser);
                    assertThat(updatedScimUser.getAliasId()).isNotBlank();
                    assertThat(updatedScimUser.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());

                    /* the version of the original user will be incremented twice when a new alias is created:
                     * 1. during the update of the original user itself (set aliasZid and update other properties)
                     * 2. after the creation of the alias entity (set aliasId to alias entity's ID) */
                    assertThat(updatedScimUser.getVersion()).isEqualTo(2);

                    final Optional<ScimUser> aliasUserOpt = readUserFromZoneIfExists(
                            updatedScimUser.getAliasId(),
                            updatedScimUser.getAliasZid()
                    );
                    assertThat(aliasUserOpt).isPresent();
                    final ScimUser aliasUser = aliasUserOpt.get();
                    assertIsCorrectAliasPair(updatedScimUser, aliasUser, zone2);

                    // the alias is newly created -> version 0
                    assertThat(aliasUser.getVersion()).isZero();

                    /* update the alias entity to check whether the non-zero version of the original entity (2) is
                     * correctly handled */
                    aliasUser.setActive(false);
                    final ScimUser updatedAliasUser = updateUser(method, zone2, aliasUser);
                    assertThat(updatedAliasUser.getVersion()).isOne(); // incremented by one

                    final Optional<ScimUser> originalUserAfter2ndUpdateOpt = readUserFromZoneIfExists(
                            createdScimUser.getId(),
                            zone1.getId()
                    );
                    assertThat(originalUserAfter2ndUpdateOpt).isPresent();
                    final ScimUser originalUserAfter2ndUpdate = originalUserAfter2ndUpdateOpt.get();
                    assertThat(originalUserAfter2ndUpdate.getVersion()).isEqualTo(3); // incremented by one
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_ConflictingUserAlreadyExistsInAliasZone_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_ConflictingUserAlreadyExistsInAliasZone(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_ConflictingUserAlreadyExistsInAliasZone_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_ConflictingUserAlreadyExistsInAliasZone(method, customZone, uaaZone);
                }

                private void shouldReject_ConflictingUserAlreadyExistsInAliasZone(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    // create an IdP in zone 1 with an alias in zone 2 and a user without alias
                    final ScimUser createdUserWithoutAlias = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    // create a user with the same username in zone 2
                    final ScimUser conflictingUser = buildScimUser(
                            createdUserWithoutAlias.getOrigin(),
                            zone2.getId(),
                            null,
                            null
                    );
                    createScimUser(zone2, conflictingUser);

                    // try to update the user with aliasZid set to zone 2 - should fail
                    createdUserWithoutAlias.setAliasZid(zone2.getId());
                    shouldRejectUpdate(method, zone1, createdUserWithoutAlias, HttpStatus.CONFLICT);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OriginIdpHasNoAlias_UaaToCustomZone(final HttpMethodEnum method) throws Exception {
                    shouldReject_OriginIdpHasNoAlias(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OriginIdpHasNoAlias_CustomToUaaZone(final HttpMethodEnum method) throws Exception {
                    shouldReject_OriginIdpHasNoAlias(method, customZone, uaaZone);
                }

                private void shouldReject_OriginIdpHasNoAlias(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Exception {
                    // create an IdP without alias
                    final IdentityProvider<?> idpWithoutAlias = buildIdpWithAliasProperties(
                            zone1.getId(),
                            null,
                            null,
                            RANDOM_STRING_GENERATOR.generate(),
                            OIDC10
                    );
                    final IdentityProvider<?> createdIdpWithoutAlias = createIdp(zone1, idpWithoutAlias);

                    // create a user without an alias
                    final ScimUser userWithoutAlias = buildScimUser(
                            createdIdpWithoutAlias.getOriginKey(),
                            zone1.getId(),
                            null,
                            null
                    );
                    final ScimUser createdUserWithoutAlias = createScimUser(zone1, userWithoutAlias);

                    // try to update user with aliasZid set to zone 2 - should fail
                    createdUserWithoutAlias.setAliasZid(zone2.getId());
                    shouldRejectUpdate(method, zone1, createdUserWithoutAlias, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OriginIdpHasAliasToDifferentZone(final HttpMethodEnum method) throws Throwable {
                    final IdentityZone zone1 = uaaZone;
                    final IdentityZone zone2 = customZone;
                    final IdentityZone zone3 = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

                    // create IdP in zone 1 with alias in zone 2 and user without alias
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    // try to update user with aliasZid set to a different custom zone (zone 3) - should fail
                    createdScimUser.setAliasZid(zone3.getId());
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_ReferencedAliasZoneDesNotExist(final HttpMethodEnum method) throws Throwable {
                    final IdentityZone zone1 = uaaZone;

                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, customZone)
                    );

                    // update user with aliasZid set to a non-existing - should fail
                    createdScimUser.setAliasZid(UUID.randomUUID().toString());
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasZidSetToSameZone_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_AliasZidSetToSameZone(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasZidSetToSameZone_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_AliasZidSetToSameZone(method, customZone, uaaZone);
                }

                private void shouldReject_AliasZidSetToSameZone(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    // update user with alias in same zone - should fail
                    createdScimUser.setAliasZid(zone1.getId());
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasZidSetToDifferentCustomZone(final HttpMethodEnum method) throws Throwable {
                    final IdentityZone zone1 = customZone;
                    final IdentityZone zone2 = uaaZone;

                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    // update user with aliasZid set to a different custom zone - should fail
                    final IdentityZone otherCustomZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
                    createdScimUser.setAliasZid(otherCustomZone.getId());
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @Test
                void shouldAccept_ShouldCreateNewAlias_NoZoneIdSet_UaaToCustomZone() throws Throwable {
                    shouldAccept_ShouldCreateNewAlias_NoZoneIdSet(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_ShouldCreateNewAlias_NoZoneIdSet_CustomToUaaZone() throws Throwable {
                    shouldAccept_ShouldCreateNewAlias_NoZoneIdSet(customZone, IdentityZone.getUaa());
                }

                /**
                 * This test case checks whether the alias creation still works, even when the zone ID property is not
                 * explicitly set in the request body.
                 */
                void shouldAccept_ShouldCreateNewAlias_NoZoneIdSet(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    // the update endpoint allows sending the user with an empty zone ID property
                    createdScimUser.setZoneId(null);

                    createdScimUser.setAliasZid(zone2.getId());
                    createdScimUser.setName(new ScimUser.Name("John", "Doe Jr."));

                    updateUser(HttpMethodEnum.PUT, zone1, createdScimUser);
                }
            }
        }

        @Nested
        class AliasFeatureDisabled extends UpdateBase {
            public AliasFeatureDisabled() {
                super(false);
            }

            @Nested
            class ExistingAlias {
                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyAliasPropsSetToNull_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyAliasPropsSetToNull(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyAliasPropsSetToNull_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyAliasPropsSetToNull(method, customZone, uaaZone);
                }

                private void shouldReject_OnlyAliasPropsSetToNull(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasId(UaaStringUtils.EMPTY_STRING);
                    createdScimUser.setAliasZid(UaaStringUtils.EMPTY_STRING);

                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasPropsSetToNullAndOtherPropsChanged_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_AliasPropsSetToNullAndOtherPropsChanged(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_AliasPropsSetToNullAndOtherPropsChanged_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_AliasPropsSetToNullAndOtherPropsChanged(method, customZone, uaaZone);
                }

                private void shouldReject_AliasPropsSetToNullAndOtherPropsChanged(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasId(UaaStringUtils.EMPTY_STRING);
                    createdScimUser.setAliasZid(UaaStringUtils.EMPTY_STRING);
                    final String newGivenName = "some-new-given-name";
                    createdScimUser.setName(new ScimUser.Name(newGivenName, createdScimUser.getFamilyName()));

                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_EvenIfAliasIdMissingInExistingUser_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_EvenIfAliasIdMissingInExistingUser(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_EvenIfAliasIdMissingInExistingUser_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_EvenIfAliasIdMissingInExistingUser(method, customZone, uaaZone);
                }

                private void shouldReject_EvenIfAliasIdMissingInExistingUser(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    // remove aliasId field directly in DB
                    createdScimUser.setAliasId(null);
                    final ScimUser scimUserWithIncompleteRef = updateUserViaDb(createdScimUser, zone1.getId());

                    scimUserWithIncompleteRef.setAliasZid(UaaStringUtils.EMPTY_STRING);
                    shouldRejectUpdate(method, zone1, scimUserWithIncompleteRef, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_DanglingRef_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_DanglingRef(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_DanglingRef_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_DanglingRef(method, customZone, uaaZone);
                }

                private void shouldReject_DanglingRef(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );
                    final String aliasId = createdScimUser.getAliasId();
                    assertThat(aliasId).isNotBlank();
                    final String aliasZid = createdScimUser.getAliasZid();
                    assertThat(aliasZid).isNotBlank();

                    // create dangling reference by deleting alias
                    deleteUserViaDb(aliasId, aliasZid);

                    // should reject update even if there is a dangling reference
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyNonAliasPropertiesChanged_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyNonAliasPropertiesChanged(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyNonAliasPropertiesChanged_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyNonAliasPropertiesChanged(method, customZone, uaaZone);
                }

                private void shouldReject_OnlyNonAliasPropertiesChanged(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setNickName("some-new-nickname");
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyAliasIdSetToNull_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyAliasIdSetToNull(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyAliasIdSetToNull_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyAliasIdSetToNull(method, customZone, uaaZone);
                }

                private void shouldReject_OnlyAliasIdSetToNull(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasId(null);
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyAliasZidSetToNull_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyAliasZidSetToNull(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyAliasZidSetToNull_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyAliasZidSetToNull(method, customZone, uaaZone);
                }

                private void shouldReject_OnlyAliasZidSetToNull(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasZid(null);
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }
            }

            @Nested
            class NoExistingAlias {
                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyAliasZidSet_UaaToCustomZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyAliasZidSet(method, uaaZone, customZone);
                }

                @ParameterizedTest
                @EnumSource(value = HttpMethodEnum.class, names = {"PUT", "PATCH"})
                void shouldReject_OnlyAliasZidSet_CustomToUaaZone(final HttpMethodEnum method) throws Throwable {
                    shouldReject_OnlyAliasZidSet(method, customZone, uaaZone);
                }

                private void shouldReject_OnlyAliasZidSet(
                        final HttpMethodEnum method,
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasZid(zone2.getId());
                    shouldRejectUpdate(method, zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }
            }
        }

        private ScimUser updateUser(
                final HttpMethodEnum method,
                final IdentityZone zone,
                final ScimUser scimUser
        ) throws Exception {
            final MvcResult result = updateUserAndReturnResult(method, zone, scimUser);
            assertThat(result).isNotNull();
            final MockHttpServletResponse response = result.getResponse();
            assertThat(response).isNotNull();
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            return JsonUtils.readValue(
                    response.getContentAsString(),
                    ScimUser.class
            );
        }

        private MvcResult updateUserAndReturnResult(
                final HttpMethodEnum method,
                final IdentityZone zone,
                final ScimUser scimUser
        ) throws Exception {
            final String userId = scimUser.getId();
            assertThat(userId).isNotBlank();

            MockHttpServletRequestBuilder updateRequestBuilder;
            switch (method) {
                case PUT:
                    updateRequestBuilder = put("/Users/" + userId);
                    break;
                case PATCH:
                    updateRequestBuilder = patch("/Users/" + userId);
                    break;
                default:
                    fail("Encountered invalid HTTP method: " + method);
                    return null;
            }
            updateRequestBuilder = updateRequestBuilder
                    .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getSubdomain())
                    .header("If-Match", scimUser.getVersion())
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(scimUser));

            return mockMvc.perform(updateRequestBuilder).andReturn();
        }

        private void shouldRejectUpdate(
                final HttpMethodEnum method,
                final IdentityZone zone,
                final ScimUser scimUser,
                final HttpStatus expectedStatusCode
        ) throws Exception {
            final MvcResult result = updateUserAndReturnResult(method, zone, scimUser);
            assertThat(result).isNotNull();
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatusCode.value());
        }
    }

    @Nested
    class Delete {
        abstract class DeleteBase {
            protected final boolean aliasFeatureEnabled;

            protected DeleteBase(final boolean aliasFeatureEnabled) {
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
        }

        @Nested
        class AliasFeatureEnabled extends DeleteBase {
            protected AliasFeatureEnabled() {
                super(true);
            }

            @Test
            void shouldAlsoDeleteAliasUser_UaaToCustomZone() throws Throwable {
                shouldAlsoDeleteAliasUser(uaaZone, customZone);
            }

            @Test
            void shouldAlsoDeleteAliasUser_CustomToUaaZone() throws Throwable {
                shouldAlsoDeleteAliasUser(customZone, uaaZone);
            }

            private void shouldAlsoDeleteAliasUser(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final ScimUser userWithAlias = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                final ScimUser createdUserWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createScimUser(zone1, userWithAlias)
                );

                // should remove both the user and its alias
                shouldSuccessfullyDeleteUser(createdUserWithAlias, zone1);
                assertUserDoesNotExist(createdUserWithAlias.getAliasId(), zone2.getId());
            }

            @Test
            void shouldIgnoreDanglingReference_UaaToCustomZone() throws Throwable {
                shouldIgnoreDanglingReference(uaaZone, customZone);
            }

            @Test
            void shouldIgnoreDanglingReference_CustomToUaaZone() throws Throwable {
                shouldIgnoreDanglingReference(customZone, uaaZone);
            }

            private void shouldIgnoreDanglingReference(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final ScimUser userWithAlias = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                final ScimUser createdUserWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createScimUser(zone1, userWithAlias)
                );
                assertThat(createdUserWithAlias.getAliasId()).isNotBlank();
                assertThat(createdUserWithAlias.getAliasZid()).isNotBlank();

                // create dangling reference by removing alias user directly in DB
                deleteUserViaDb(createdUserWithAlias.getAliasId(), createdUserWithAlias.getAliasZid());

                // deletion should still work
                shouldSuccessfullyDeleteUser(createdUserWithAlias, zone1);
            }
        }

        @Nested
        class AliasFeatureDisabled extends DeleteBase {
            protected AliasFeatureDisabled() {
                super(false);
            }

            @Test
            void shouldRejectDeletion_WhenAliasUserExists_UaaToCustomZone() throws Throwable {
                shouldRejectDeletion_WhenAliasUserExists(uaaZone, customZone);
            }

            @Test
            void shouldRejectDeletion_WhenAliasUserExists_CustomToUaaZone() throws Throwable {
                shouldRejectDeletion_WhenAliasUserExists(customZone, uaaZone);
            }

            private void shouldRejectDeletion_WhenAliasUserExists(
                    final IdentityZone zone1,
                    final IdentityZone zone2
            ) throws Throwable {
                final IdentityProvider<?> idpWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createIdpWithAlias(zone1, zone2)
                );

                final ScimUser userWithAlias = buildScimUser(
                        idpWithAlias.getOriginKey(),
                        zone1.getId(),
                        null,
                        zone2.getId()
                );
                final ScimUser createdUserWithAlias = executeWithTemporarilyEnabledAliasFeature(
                        aliasFeatureEnabled,
                        () -> createScimUser(zone1, userWithAlias)
                );

                shouldRejectDeletion(createdUserWithAlias.getId(), zone1, HttpStatus.BAD_REQUEST);

                // both users should still be present
                assertThat(readUserFromZoneIfExists(
                        createdUserWithAlias.getId(),
                        createdUserWithAlias.getZoneId()
                )).isPresent();
                assertThat(readUserFromZoneIfExists(
                        createdUserWithAlias.getAliasId(),
                        createdUserWithAlias.getAliasZid()
                )).isPresent();
            }

            private void shouldRejectDeletion(
                    final String userId,
                    final IdentityZone zone,
                    final HttpStatus expectedStatusCode
            ) throws Exception {
                assertThat(expectedStatusCode.isError()).isTrue();
                final MvcResult result = deleteScimUserAndReturnResult(userId, zone);
                assertThat(result).isNotNull();
                final MockHttpServletResponse response = result.getResponse();
                assertThat(response).isNotNull();
                assertThat(response.getStatus()).isEqualTo(expectedStatusCode.value());
            }
        }

        private void shouldSuccessfullyDeleteUser(final ScimUser user, final IdentityZone zone) throws Exception {
            final MvcResult result = deleteScimUserAndReturnResult(user.getId(), zone);
            assertThat(result.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        }

        private MvcResult deleteScimUserAndReturnResult(final String userId, final IdentityZone zone) throws Exception {
            final MockHttpServletRequestBuilder deleteRequestBuilder = delete("/Users/" + userId)
                    .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getSubdomain());
            return mockMvc.perform(deleteRequestBuilder).andReturn();
        }

        private void assertUserDoesNotExist(final String id, final String zoneId) throws Exception {
            final Optional<ScimUser> user = readUserFromZoneIfExists(id, zoneId);
            assertThat(user).isNotPresent();
        }
    }

    private ScimUser createIdpAndUserWithAlias(
            final IdentityZone zone1,
            final IdentityZone zone2
    ) throws Throwable {
        final IdentityProvider<?> idpWithAlias = createIdpWithAlias(zone1, zone2);

        final ScimUser scimUser = buildScimUser(
                idpWithAlias.getOriginKey(),
                zone1.getId(),
                null,
                zone2.getId()
        );
        return createScimUser(zone1, scimUser);
    }

    private static void assertIsCorrectAliasPair(
            final ScimUser originalUser,
            final ScimUser aliasUser,
            final IdentityZone aliasZone
    ) {
        assertThat(originalUser).isNotNull();
        assertThat(aliasUser).isNotNull();

        // 'id' field will differ
        assertThat(originalUser.getId()).isNotBlank().isNotEqualTo(aliasUser.getId());
        assertThat(aliasUser.getId()).isNotBlank().isNotEqualTo(originalUser.getId());

        // 'aliasId' and 'aliasZid' should point to the other entity, respectively
        assertThat(originalUser.getAliasId()).isNotBlank().isEqualTo(aliasUser.getId());
        assertThat(aliasUser.getAliasId()).isNotBlank().isEqualTo(originalUser.getId());
        assertThat(originalUser.getAliasZid()).isNotBlank().isEqualTo(aliasUser.getZoneId());
        assertThat(aliasUser.getAliasZid()).isNotBlank().isEqualTo(originalUser.getZoneId());

        // the other properties should be equal

        assertThat(originalUser.getUserName()).isEqualTo(aliasUser.getUserName());
        assertThat(originalUser.getName()).isNotNull();
        assertThat(aliasUser.getName()).isNotNull();
        assertThat(originalUser.getName().getGivenName()).isNotBlank().isEqualTo(aliasUser.getName().getGivenName());
        assertThat(originalUser.getName().getFamilyName()).isNotBlank().isEqualTo(aliasUser.getName().getFamilyName());

        assertThat(originalUser.getOrigin()).isEqualTo(aliasUser.getOrigin());
        assertThat(originalUser.getExternalId()).isEqualTo(aliasUser.getExternalId());

        assertThat(originalUser.getEmails()).isEqualTo(aliasUser.getEmails());
        assertThat(originalUser.getPrimaryEmail()).isEqualTo(aliasUser.getPrimaryEmail());
        assertThat(originalUser.getPhoneNumbers()).isEqualTo(aliasUser.getPhoneNumbers());

        assertThat(originalUser.isActive()).isEqualTo(aliasUser.isActive());
        assertThat(originalUser.isVerified()).isEqualTo(aliasUser.isVerified());

        // in the API response, the password and salt must be null for both the original and the alias user
        assertThat(originalUser.getPassword()).isNull();
        assertThat(originalUser.getSalt()).isNull();
        assertThat(aliasUser.getPassword()).isNull();
        assertThat(aliasUser.getSalt()).isNull();

        // approvals must be empty for the alias user
        assertThat(aliasUser.getApprovals()).isEmpty();

        // apart from the default groups of the alias zone, the alias user must have no groups
        final Optional<List<String>> defaultGroupNamesAliasZoneOpt = Optional.ofNullable(aliasZone.getConfig())
                .map(IdentityZoneConfiguration::getUserConfig)
                .map(UserConfig::getDefaultGroups);
        assertThat(defaultGroupNamesAliasZoneOpt).isPresent();
        final List<String> defaultGroupNamesAliasZone = defaultGroupNamesAliasZoneOpt.get();
        assertThat(aliasUser.getGroups()).hasSize(defaultGroupNamesAliasZone.size());
        final List<String> directGroupNamesAliasUser = aliasUser.getGroups().stream()
                .filter(group -> group.getType() == DIRECT)
                .map(ScimUser.Group::getDisplay)
                .toList();
        assertThat(directGroupNamesAliasUser).hasSameElementsAs(defaultGroupNamesAliasZone);

        final ScimMeta originalUserMeta = originalUser.getMeta();
        assertThat(originalUserMeta).isNotNull();
        final ScimMeta aliasUserMeta = aliasUser.getMeta();
        assertThat(aliasUserMeta).isNotNull();
        // 'created', 'lastModified' and 'version' are expected to be different
        assertThat(originalUserMeta.getAttributes()).isEqualTo(aliasUserMeta.getAttributes());

        assertThat(originalUser.getSchemas()).isEqualTo(aliasUser.getSchemas());
    }

    private ScimUser buildScimUser(
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

        scimUser.setUserName(TEST_USERNAME);
        scimUser.setName(new ScimUser.Name("John", "Doe"));
        scimUser.setPrimaryEmail(TEST_USERNAME + "@example.com");
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

    private ScimUser createIdpWithAliasAndUserWithoutAlias(
            final IdentityZone zone1,
            final IdentityZone zone2
    ) throws Throwable {
        final IdentityProvider<?> idpWithAlias = createIdpWithAlias(zone1, zone2);

        // create user without alias
        final ScimUser scimUser = buildScimUser(
                idpWithAlias.getOriginKey(),
                zone1.getId(),
                null,
                null
        );
        return createScimUser(zone1, scimUser);
    }

    private Optional<ScimUser> readUserFromZoneByUsername(String username, IdentityZone zone) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/Users")
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                .param("filter", "userName eq \"%s\"".formatted(username));
        final MvcResult getResult = mockMvc.perform(getRequestBuilder)
                .andExpect(status().isOk())
                .andReturn();
        final SearchResults<ScimUser> searchResults = JsonUtils.readValue(
                getResult.getResponse().getContentAsString(),
                new TypeReference<>() {
                }
        );
        assertThat(searchResults).isNotNull();
        return searchResults.getResources().stream().findFirst();
    }

    private Optional<ScimUser> readUserFromZoneIfExists(final String id, final String zoneId) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/Users/" + id)
                .header(IdentityZoneSwitchingFilter.HEADER, zoneId)
                .header("Authorization", "Bearer " + getAccessTokenForZone(zoneId));
        final MvcResult getResult = mockMvc.perform(getRequestBuilder).andReturn();
        final int responseStatus = getResult.getResponse().getStatus();
        assertThat(responseStatus).isIn(404, 200);

        switch (responseStatus) {
            case 404:
                return Optional.empty();
            case 200:
                final ScimUser responseBody = JsonUtils.readValue(
                        getResult.getResponse().getContentAsString(),
                        ScimUser.class
                );
                return Optional.ofNullable(responseBody);
            default:
                // should not happen
                return Optional.empty();
        }
    }

    private ScimUser updateUserViaDb(final ScimUser user, final String zoneId) {
        final JdbcScimUserProvisioning scimUserProvisioning = webApplicationContext
                .getBean(JdbcScimUserProvisioning.class);
        assertThat(user.getId()).isNotBlank();
        return scimUserProvisioning.update(user.getId(), user, zoneId);
    }

    private void deleteUserViaDb(final String id, final String zoneId) {
        final JdbcScimUserProvisioning scimUserProvisioning = webApplicationContext
                .getBean(JdbcScimUserProvisioning.class);
        final int rowsDeleted = scimUserProvisioning.deleteByUser(id, zoneId);
        assertThat(rowsDeleted).isOne();
    }

    @Override
    protected void arrangeAliasFeatureEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(idpEntityAliasHandler, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(identityProviderEndpoints, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(scimUserAliasHandler, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(scimUserEndpoints, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(scimUserService, "aliasEntitiesEnabled", enabled);
    }
}
