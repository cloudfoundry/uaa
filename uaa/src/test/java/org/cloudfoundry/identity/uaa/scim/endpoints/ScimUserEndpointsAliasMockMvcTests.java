package org.cloudfoundry.identity.uaa.scim.endpoints;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.core.type.TypeReference;

@DefaultTestContext
public class ScimUserEndpointsAliasMockMvcTests extends AliasMockMvcTestBase {
    private IdentityProviderAliasHandler idpEntityAliasHandler;
    private IdentityProviderEndpoints identityProviderEndpoints;
    private ScimUserAliasHandler scimUserAliasHandler;
    private ScimUserEndpoints scimUserEndpoints;

    @BeforeEach
    void setUp() throws Exception {
        setUpTokensAndCustomZone();

        idpEntityAliasHandler = requireNonNull(webApplicationContext.getBean(IdentityProviderAliasHandler.class));
        identityProviderEndpoints = requireNonNull(webApplicationContext.getBean(IdentityProviderEndpoints.class));
        scimUserAliasHandler = requireNonNull(webApplicationContext.getBean(ScimUserAliasHandler.class));
        scimUserEndpoints = requireNonNull(webApplicationContext.getBean(ScimUserEndpoints.class));
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

                // find alias user
                final List<ScimUser> usersZone2 = readRecentlyCreatedUsersInZone(zone2);
                final Optional<ScimUser> aliasUserOpt = usersZone2.stream()
                        .filter(user -> user.getId().equals(createdScimUser.getAliasId()))
                        .findFirst();
                assertThat(aliasUserOpt).isPresent();

                assertIsCorrectAliasPair(createdScimUser, aliasUserOpt.get());
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

    @Nested
    class UpdatePut {
        abstract class UpdatePutBase {
            protected final boolean aliasFeatureEnabled;

            protected UpdatePutBase(final boolean aliasFeatureEnabled) {
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
            final void shouldReject_NoExistingAlias_AliasIdSet_UaaToCustomZone() throws Throwable {
                shouldReject_NoExistingAlias_AliasIdSet(IdentityZone.getUaa(), customZone);
            }

            @Test
            final void shouldReject_NoExistingAlias_AliasIdSet_CustomToUaaZone() throws Throwable {
                shouldReject_NoExistingAlias_AliasIdSet(customZone, IdentityZone.getUaa());
            }

            private void shouldReject_NoExistingAlias_AliasIdSet(
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
                shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
            }

        }

        @Nested
        class AliasFeatureEnabled extends UpdatePutBase {
            public AliasFeatureEnabled() {
                super(true);
            }

            @Nested
            class ExistingAlias {
                @Test
                void shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser_UaaToCustomZone() throws Throwable {
                    shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser_CustomToUaaZone() throws Throwable {
                    shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_AliasPropsNotChanged_ShouldPropagateChangesToAliasUser(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    final String newUserName = "some-new-username";
                    createdScimUser.setUserName(newUserName);
                    final ScimUser updatedScimUser = updateUserPut(zone1, createdScimUser);
                    assertThat(updatedScimUser.getUserName()).isEqualTo(newUserName);

                    final Optional<ScimUser> aliasUserOpt = readUserFromZoneIfExists(
                            createdScimUser.getAliasId(),
                            zone2.getId()
                    );
                    assertThat(aliasUserOpt).isPresent();

                    assertIsCorrectAliasPair(updatedScimUser, aliasUserOpt.get());
                }

                @Test
                void shouldAccept_ShouldFixDanglingReference_UaaToCustomZone() throws Throwable {
                    shouldAccept_ShouldFixDanglingReference(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_ShouldFixDanglingReference_CustomToUaaZone() throws Throwable {
                    shouldAccept_ShouldFixDanglingReference(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_ShouldFixDanglingReference(
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
                    final ScimUser updatedScimUser = updateUserPut(zone1, createdScimUser);
                    assertThat(updatedScimUser.getUserName()).isEqualTo(newUserName);

                    // the dangling reference should be fixed
                    final String newAliasId = updatedScimUser.getAliasId();
                    assertThat(newAliasId).isNotBlank().isNotEqualTo(initialAliasId);
                    final Optional<ScimUser> newAliasUserOpt = readUserFromZoneIfExists(
                            newAliasId,
                            zone2.getId()
                    );
                    assertThat(newAliasUserOpt).isPresent();
                    assertIsCorrectAliasPair(updatedScimUser, newAliasUserOpt.get());
                }

                @Test
                void shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone_UaaToCustomZone() throws Throwable {
                    shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone_CustomToUaaZone() throws Throwable {
                    shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_DanglingReferenceButConflictingUserAlreadyExistsInAliasZone(
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
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.CONFLICT);
                }

                @Test
                void shouldReject_AliasIdSetInExistingButAliasZidNot_UaaToCustomZone() throws Throwable {
                    shouldReject_AliasIdSetInExistingButAliasZidNot(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_AliasIdSetInExistingButAliasZidNot_CustomToUaaZone() throws Throwable {
                    shouldReject_AliasIdSetInExistingButAliasZidNot(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_AliasIdSetInExistingButAliasZidNot(
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
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.INTERNAL_SERVER_ERROR);
                }

                @Test
                void shouldReject_AliasPropertiesChanged_UaaToCustomZone() throws Throwable {
                    shouldReject_AliasPropertiesChanged(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_AliasPropertiesChanged_CustomToUaaZone() throws Throwable {
                    shouldReject_AliasPropertiesChanged(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_AliasPropertiesChanged(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasZid(null);
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @Test
                void shouldReject_DanglingReferenceAndZoneNotExisting_UaaToCustomZone() throws Throwable {
                    shouldReject_DanglingReferenceAndZoneNotExisting(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_DanglingReferenceAndZoneNotExisting_CustomToUaaZone() throws Throwable {
                    shouldReject_DanglingReferenceAndZoneNotExisting(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_DanglingReferenceAndZoneNotExisting(
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
                    shouldRejectUpdatePut(zone1, userWithDanglingRef, HttpStatus.UNPROCESSABLE_ENTITY);
                }
            }

            @Nested
            class NoExistingAlias {
                @Test
                void shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet_UaaToCustomZone() throws Throwable {
                    shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet_CustomToUaaZone() throws Throwable {
                    shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_ShouldCreateNewAliasIfOnlyAliasZidSet(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasZid(zone2.getId());
                    final ScimUser updatedScimUser = updateUserPut(zone1, createdScimUser);
                    assertThat(updatedScimUser.getAliasId()).isNotBlank();
                    assertThat(updatedScimUser.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());

                    final Optional<ScimUser> aliasUserOpt = readUserFromZoneIfExists(
                            updatedScimUser.getAliasId(),
                            updatedScimUser.getAliasZid()
                    );
                    assertThat(aliasUserOpt).isPresent();
                    final ScimUser aliasUser = aliasUserOpt.get();
                    assertIsCorrectAliasPair(updatedScimUser, aliasUser);
                }

                @Test
                void shouldReject_ConflictingUserAlreadyExistsInAliasZone_UaaToCustomZone() throws Throwable {
                    shouldReject_ConflictingUserAlreadyExistsInAliasZone(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_ConflictingUserAlreadyExistsInAliasZone_CustomToUaaZone() throws Throwable {
                    shouldReject_ConflictingUserAlreadyExistsInAliasZone(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_ConflictingUserAlreadyExistsInAliasZone(
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
                    shouldRejectUpdatePut(zone1, createdUserWithoutAlias, HttpStatus.CONFLICT);
                }

                @Test
                void shouldReject_OriginIdpHasNoAlias_UaaToCustomZone() throws Exception {
                    shouldReject_OriginIdpHasNoAlias(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_OriginIdpHasNoAlias_CustomToUaaZone() throws Exception {
                    shouldReject_OriginIdpHasNoAlias(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_OriginIdpHasNoAlias(
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
                    shouldRejectUpdatePut(zone1, createdUserWithoutAlias, HttpStatus.BAD_REQUEST);
                }

                @Test
                void shouldReject_OriginIdpHasAliasToDifferentZone() throws Throwable {
                    final IdentityZone zone1 = IdentityZone.getUaa();
                    final IdentityZone zone2 = customZone;
                    final IdentityZone zone3 = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

                    // create IdP in zone 1 with alias in zone 2 and user without alias
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    // try to update user with aliasZid set to a different custom zone (zone 3) - should fail
                    createdScimUser.setAliasZid(zone3.getId());
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @Test
                void shouldReject_ReferencedAliasZoneDesNotExist() throws Throwable {
                    final IdentityZone zone1 = IdentityZone.getUaa();

                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, customZone)
                    );

                    // update user with aliasZid set to a non-existing - should fail
                    createdScimUser.setAliasZid(UUID.randomUUID().toString());
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @Test
                void shouldReject_AliasZidSetToSameZone_UaaToCustomZone() throws Throwable {
                    shouldReject_AliasZidSetToSameZone(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_AliasZidSetToSameZone_CustomToUaaZone() throws Throwable {
                    shouldReject_AliasZidSetToSameZone(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_AliasZidSetToSameZone(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    // update user with alias in same zone - should fail
                    createdScimUser.setAliasZid(zone1.getId());
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                @Test
                void shouldReject_AliasZidSetToDifferentCustomZone() throws Throwable {
                    final IdentityZone zone1 = customZone;
                    final IdentityZone zone2 = IdentityZone.getUaa();

                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    // update user with aliasZid set to a different custom zone - should fail
                    final IdentityZone otherCustomZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
                    createdScimUser.setAliasZid(otherCustomZone.getId());
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }
            }
        }

        @Nested
        class AliasFeatureDisabled extends UpdatePutBase {
            public AliasFeatureDisabled() {
                super(false);
            }

            @Nested
            class ExistingAlias {
                @Test
                void shouldAccept_OnlyAliasPropsSetToNull_UaaToCustomZone() throws Throwable {
                    shouldAccept_OnlyAliasPropsSetToNull(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_OnlyAliasPropsSetToNull_CustomToUaaZone() throws Throwable {
                    shouldAccept_OnlyAliasPropsSetToNull(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_OnlyAliasPropsSetToNull(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    final String initialAliasId = createdScimUser.getAliasId();
                    assertThat(initialAliasId).isNotBlank();

                    final String initialAliasZid = createdScimUser.getAliasZid();
                    assertThat(initialAliasZid).isNotBlank().isEqualTo(zone2.getId());

                    createdScimUser.setAliasId(null);
                    createdScimUser.setAliasZid(null);
                    final ScimUser updatedScimUser = updateUserPut(zone1, createdScimUser);

                    assertThat(updatedScimUser.getAliasId()).isBlank();
                    assertThat(updatedScimUser.getAliasZid()).isBlank();

                    // reference should also be broken in alias user
                    assertReferenceIsBrokenInAlias(initialAliasId, initialAliasZid);
                }

                @Test
                void shouldAccept_AliasPropsSetToNullAndOtherPropsChanged_UaaToCustomZone() throws Throwable {
                    shouldAccept_AliasPropsSetToNullAndOtherPropsChanged(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_AliasPropsSetToNullAndOtherPropsChanged_CustomToUaaZone() throws Throwable {
                    shouldAccept_AliasPropsSetToNullAndOtherPropsChanged(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_AliasPropsSetToNullAndOtherPropsChanged(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    final String initialAliasId = createdScimUser.getAliasId();
                    assertThat(initialAliasId).isNotBlank();

                    final String initialAliasZid = createdScimUser.getAliasZid();
                    assertThat(initialAliasZid).isNotBlank().isEqualTo(zone2.getId());

                    createdScimUser.setAliasId(null);
                    createdScimUser.setAliasZid(null);
                    final String newNickName = "some-new-nickname";
                    createdScimUser.setNickName(newNickName);
                    final ScimUser updatedScimUser = updateUserPut(zone1, createdScimUser);

                    assertThat(updatedScimUser.getAliasId()).isBlank();
                    assertThat(updatedScimUser.getAliasZid()).isBlank();

                    // reference should also be broken in alias user
                    assertReferenceIsBrokenInAlias(initialAliasId, initialAliasZid);
                    final Optional<ScimUser> aliasUserOpt = readUserFromZoneIfExists(initialAliasId, initialAliasZid);
                    assertThat(aliasUserOpt).isPresent();
                    assertThat(aliasUserOpt.get().getNickName()).isNotEqualTo(newNickName);
                }

                @Test
                void shouldAccept_ShouldIgnoreAliasIdMissingInExistingUser_UaaToCustomZone() throws Throwable {
                    shouldAccept_ShouldIgnoreAliasIdMissingInExistingUser(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_ShouldIgnoreAliasIdMissingInExistingUser_CustomToUaaZone() throws Throwable {
                    shouldAccept_ShouldIgnoreAliasIdMissingInExistingUser(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_ShouldIgnoreAliasIdMissingInExistingUser(
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

                    scimUserWithIncompleteRef.setAliasZid(null);
                    final ScimUser updatedScimUser = updateUserViaDb(scimUserWithIncompleteRef, zone1.getId());
                    assertThat(updatedScimUser.getAliasId()).isBlank();
                    assertThat(updatedScimUser.getAliasZid()).isBlank();
                }

                @Test
                void shouldAccept_ShouldIgnoreDanglingRef_UaaToCustomZone() throws Throwable {
                    shouldAccept_ShouldIgnoreDanglingRef(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldAccept_ShouldIgnoreDanglingRef_CustomToUaaZone() throws Throwable {
                    shouldAccept_ShouldIgnoreDanglingRef(customZone, IdentityZone.getUaa());
                }

                private void shouldAccept_ShouldIgnoreDanglingRef(
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

                    // should ignore dangling reference in update
                    createdScimUser.setAliasId(null);
                    createdScimUser.setAliasZid(null);
                    updateUserPut(zone1, createdScimUser);
                }

                @Test
                void shouldReject_OtherPropsChangedWhileAliasPropsNotDeleted_UaaToCustomZone() throws Throwable {
                    shouldReject_OtherPropsChangedWhileAliasPropsNotDeleted(IdentityZone.getUaa(), customZone);
                }

                @Test
                void shouldReject_OtherPropsChangedWhileAliasPropsNotDeleted_CustomToUaaZone() throws Throwable {
                    shouldReject_OtherPropsChangedWhileAliasPropsNotDeleted(customZone, IdentityZone.getUaa());
                }

                private void shouldReject_OtherPropsChangedWhileAliasPropsNotDeleted(
                        final IdentityZone zone1,
                        final IdentityZone zone2
                ) throws Throwable {
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setNickName("some-new-nickname");
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
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
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasId(null);
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
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
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpAndUserWithAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasZid(null);
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }

                private void assertReferenceIsBrokenInAlias(
                        final String initialAliasId,
                        final String initialAliasZid
                ) throws Exception {
                    final Optional<ScimUser> aliasUserOpt = readUserFromZoneIfExists(
                            initialAliasId,
                            initialAliasZid
                    );
                    assertThat(aliasUserOpt).isPresent();
                    final ScimUser aliasUser = aliasUserOpt.get();
                    assertThat(aliasUser.getAliasId()).isBlank();
                    assertThat(aliasUser.getAliasZid()).isBlank();
                }
            }

            @Nested
            class NoExistingAlias {
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
                    final ScimUser createdScimUser = executeWithTemporarilyEnabledAliasFeature(
                            aliasFeatureEnabled,
                            () -> createIdpWithAliasAndUserWithoutAlias(zone1, zone2)
                    );

                    createdScimUser.setAliasZid(zone2.getId());
                    shouldRejectUpdatePut(zone1, createdScimUser, HttpStatus.BAD_REQUEST);
                }
            }
        }

        private ScimUser updateUserPut(final IdentityZone zone, final ScimUser scimUser) throws Exception {
            final MvcResult result = updateUserPutAndReturnResult(zone, scimUser);
            final MockHttpServletResponse response = result.getResponse();
            assertThat(response).isNotNull();
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            return JsonUtils.readValue(
                    response.getContentAsString(),
                    ScimUser.class
            );
        }

        private MvcResult updateUserPutAndReturnResult(final IdentityZone zone, final ScimUser scimUser) throws Exception {
            final String userId = scimUser.getId();
            assertThat(userId).isNotBlank();
            final MockHttpServletRequestBuilder updateRequestBuilder = put("/Users/" + userId)
                    .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getSubdomain())
                    .header("If-Match", scimUser.getVersion())
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(scimUser));
            return mockMvc.perform(updateRequestBuilder).andReturn();
        }

        private void shouldRejectUpdatePut(
                final IdentityZone zone,
                final ScimUser scimUser,
                final HttpStatus expectedStatusCode
        ) throws Exception {
            final MvcResult result = updateUserPutAndReturnResult(zone, scimUser);
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatusCode.value());
        }
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

            @Test
            final void shouldIgnoreDanglingReference_UaaToCustomZone() throws Throwable {
                shouldIgnoreDanglingReference(IdentityZone.getUaa(), customZone);
            }

            @Test
            final void shouldIgnoreDanglingReference_CustomToUaaZone() throws Throwable {
                shouldIgnoreDanglingReference(customZone, IdentityZone.getUaa());
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
        class AliasFeatureEnabled extends DeleteBase {
            protected AliasFeatureEnabled() {
                super(true);
            }

            @Test
            void shouldAlsoDeleteAliasUser_UaaToCustomZone() throws Throwable {
                shouldAlsoDeleteAliasUser(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldAlsoDeleteAliasUser_CustomToUaaZone() throws Throwable {
                shouldAlsoDeleteAliasUser(customZone, IdentityZone.getUaa());
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
        }

        @Nested
        class AliasFeatureDisabled extends DeleteBase {
            protected AliasFeatureDisabled() {
                super(false);
            }

            @Test
            void shouldBreakReferenceToAliasUser_UaaToCustomZone() throws Throwable {
                shouldBreakReferenceToAliasUser(IdentityZone.getUaa(), customZone);
            }

            @Test
            void shouldBreakReferenceToAliasUser_CustomToUaaZone() throws Throwable {
                shouldBreakReferenceToAliasUser(customZone, IdentityZone.getUaa());
            }

            private void shouldBreakReferenceToAliasUser(
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

                shouldSuccessfullyDeleteUser(createdUserWithAlias, zone1);

                // the alias user should still be present with only its reference to the original user removed
                final Optional<ScimUser> aliasUserOpt = readUserFromZoneIfExists(
                        createdUserWithAlias.getAliasId(),
                        zone2.getId()
                );
                assertThat(aliasUserOpt).isPresent();
                final ScimUser aliasUser = aliasUserOpt.get();
                assertThat(aliasUser.getAliasId()).isBlank();
                assertThat(aliasUser.getAliasZid()).isBlank();
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

    private static void assertIsCorrectAliasPair(final ScimUser originalUser, final ScimUser aliasUser) {
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
        assertThat(originalUser.getUserType()).isEqualTo(aliasUser.getUserType());

        assertThat(originalUser.getOrigin()).isEqualTo(aliasUser.getOrigin());
        assertThat(originalUser.getExternalId()).isEqualTo(aliasUser.getExternalId());

        assertThat(originalUser.getTitle()).isEqualTo(aliasUser.getTitle());
        assertThat(originalUser.getName()).isEqualTo(aliasUser.getName());
        assertThat(originalUser.getDisplayName()).isEqualTo(aliasUser.getDisplayName());
        assertThat(originalUser.getNickName()).isEqualTo(aliasUser.getNickName());

        assertThat(originalUser.getEmails()).isEqualTo(aliasUser.getEmails());
        assertThat(originalUser.getPrimaryEmail()).isEqualTo(aliasUser.getPrimaryEmail());
        assertThat(originalUser.getPhoneNumbers()).isEqualTo(aliasUser.getPhoneNumbers());

        assertThat(originalUser.getLocale()).isEqualTo(aliasUser.getLocale());
        assertThat(originalUser.getPreferredLanguage()).isEqualTo(aliasUser.getPreferredLanguage());
        assertThat(originalUser.getTimezone()).isEqualTo(aliasUser.getTimezone());

        assertThat(originalUser.getProfileUrl()).isEqualTo(aliasUser.getProfileUrl());

        assertThat(originalUser.getPassword()).isEqualTo(aliasUser.getPassword());
        assertThat(originalUser.getSalt()).isEqualTo(aliasUser.getSalt());
        assertThat(originalUser.getPasswordLastModified()).isEqualTo(aliasUser.getPasswordLastModified());
        assertThat(originalUser.getLastLogonTime()).isEqualTo(aliasUser.getLastLogonTime());

        assertThat(originalUser.isActive()).isEqualTo(aliasUser.isActive());
        assertThat(originalUser.isVerified()).isEqualTo(aliasUser.isVerified());

        // TODO groups and approvals

        final ScimMeta originalUserMeta = originalUser.getMeta();
        assertThat(originalUserMeta).isNotNull();
        final ScimMeta aliasUserMeta = aliasUser.getMeta();
        assertThat(aliasUserMeta).isNotNull();
        // 'created', 'lastModified' and 'version' are expected to be different
        assertThat(originalUserMeta.getAttributes()).isEqualTo(aliasUserMeta.getAttributes());

        assertThat(originalUser.getSchemas()).isEqualTo(aliasUser.getSchemas());
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
        assertThat(rowsDeleted).isEqualTo(1);
    }

    @Override
    protected void arrangeAliasFeatureEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(idpEntityAliasHandler, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(identityProviderEndpoints, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(scimUserAliasHandler, "aliasEntitiesEnabled", enabled);
        ReflectionTestUtils.setField(scimUserEndpoints, "aliasEntitiesEnabled", enabled);
    }
}
