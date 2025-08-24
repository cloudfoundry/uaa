package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.apache.commons.lang3.tuple.Pair;
import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.scim.services.ScimUserService;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.util.StringUtils.hasText;

@ExtendWith(MockitoExtension.class)
class ScimUserEndpointsAliasTests {
    private static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR = new AlphanumericRandomValueStringGenerator(5);

    @Mock
    private IdentityZoneManager identityZoneManager;
    @Mock
    private IsSelfCheck isSelfCheck;
    @Mock
    private ScimUserProvisioning scimUserProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;
    @Mock
    private ResourceMonitor<ScimUser> scimUserResourceMonitor;
    @Mock
    private PasswordValidator passwordValidator;
    @Mock
    private ExpiringCodeStore expiringCodeStore;
    @Mock
    private ApprovalStore approvalStore;
    @Mock
    private ScimGroupMembershipManager scimGroupMembershipManager;
    @Mock
    private ScimUserAliasHandler scimUserAliasHandler;
    @Mock
    private TransactionTemplate transactionTemplate;
    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    private ScimUserEndpoints scimUserEndpoints;
    private String aliasZid;
    private String origin;

    @BeforeEach
    void setUp() {
        final ScimUserService scimUserService = new ScimUserService(
                scimUserAliasHandler,
                scimUserProvisioning,
                identityZoneManager,
                transactionTemplate,
                true // alias entities are enabled
        );

        scimUserEndpoints = new ScimUserEndpoints(
                identityZoneManager,
                isSelfCheck,
                scimUserProvisioning,
                identityProviderProvisioning,
                scimUserResourceMonitor,
                Collections.emptyMap(),
                passwordValidator,
                expiringCodeStore,
                approvalStore,
                scimGroupMembershipManager,
                scimUserService,
                scimUserAliasHandler,
                transactionTemplate,
                true, // alias entities are enabled
                500
        );

        aliasZid = RANDOM_STRING_GENERATOR.generate();
        origin = RANDOM_STRING_GENERATOR.generate();

        // mock user creation -> adds new random ID
        lenient().when(scimUserProvisioning.createUser(
                any(ScimUser.class),
                anyString(),
                anyString()
        )).then(invocationOnMock -> {
            final String id = UUID.randomUUID().toString();
            final ScimUser scimUser = invocationOnMock.getArgument(0);
            final String idzId = invocationOnMock.getArgument(2);
            scimUser.setId(id);
            scimUser.setZoneId(idzId);
            return scimUser;
        });

        lenient().when(transactionTemplate.execute(any())).then(invocationOnMock -> {
            final TransactionCallback<?> callback = invocationOnMock.getArgument(0);
            return callback != null ? callback.doInTransaction(mock(TransactionStatus.class)) : null;
        });
    }

    private void arrangeCurrentIdz(final String idzId) {
        lenient().when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(idzId);
    }

    private static ScimUser buildScimUser(final String idzId, final String origin) {
        final ScimUser user = new ScimUser();
        user.setOrigin(origin);
        final String email = "john.doe@example.com";
        user.setUserName(email);
        user.setName(new ScimUser.Name("John", "Doe"));
        user.setZoneId(idzId);
        user.setPrimaryEmail(email);
        return user;
    }

    @Nested
    class Create {
        @BeforeEach
        void setUp() {
            arrangeCurrentIdz(UAA);

            // mock aliasHandler.ensureConsistencyOfAliasEntity -> adds random alias ID to original user
            lenient().when(scimUserAliasHandler.ensureConsistencyOfAliasEntity(
                    any(ScimUser.class),
                    eq(null)
            )).then(invocationOnMock -> {
                final ScimUser scimUser = invocationOnMock.getArgument(0);
                if (hasText(scimUser.getAliasZid())) {
                    // mock ID of newly created alias user
                    scimUser.setAliasId(UUID.randomUUID().toString());
                }
                return scimUser;
            });
        }

        @Test
        void shouldThrow_WhenAliasPropertiesAreInvalid() {
            final ScimUser user = buildScimUser(UAA, origin);

            when(scimUserAliasHandler.aliasPropertiesAreValid(user, null)).thenReturn(false);

            final MockHttpServletRequest req = new MockHttpServletRequest();
            final MockHttpServletResponse res = new MockHttpServletResponse();
            assertThatThrownBy(() -> scimUserEndpoints.createUser(user, req, res))
                    .isInstanceOf(ScimException.class)
                    .hasMessage("Alias ID and/or alias ZID are invalid.")
                    .satisfies(e -> assertThat(((ScimException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        }

        @Test
        void shouldThrow_WhenAliasIsNotPresent() {
            final ScimUser user = buildScimUser(UAA, origin);

            when(scimUserAliasHandler.aliasPropertiesAreValid(user, null)).thenReturn(true);
            when(scimUserAliasHandler.ensureConsistencyOfAliasEntity(user, null)).thenReturn(null);

            final MockHttpServletRequest req = new MockHttpServletRequest();
            final MockHttpServletResponse res = new MockHttpServletResponse();
            assertThatThrownBy(() ->
                    scimUserEndpoints.createUser(user, req, res))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("The persisted user is not present after handling the alias.");
        }

        @Test
        void shouldReturnOriginalUser() {
            final ScimUser user = buildScimUser(UAA, origin);
            user.setAliasZid(aliasZid);

            when(scimUserAliasHandler.aliasPropertiesAreValid(user, null)).thenReturn(true);

            final ScimUser response = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
            assertThat(response.getAliasId()).isNotBlank();
        }

        @Test
        void shouldThrowScimException_WhenAliasCreationFailed() {
            final ScimUser user = buildScimUser(UAA, origin);
            user.setAliasZid(aliasZid);

            when(scimUserAliasHandler.aliasPropertiesAreValid(user, null)).thenReturn(true);

            final String errorMessage = "Creation of alias user failed.";
            when(scimUserAliasHandler.ensureConsistencyOfAliasEntity(user, null))
                    .thenThrow(new EntityAliasFailedException(errorMessage, 400, null));

            final MockHttpServletRequest req = new MockHttpServletRequest();
            final MockHttpServletResponse res = new MockHttpServletResponse();
            assertThatThrownBy(() -> scimUserEndpoints.createUser(user, req, res))
                    .isInstanceOf(ScimException.class)
                    .hasMessage(errorMessage)
                    .satisfies(e -> assertThat(((ScimException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        }
    }

    @Nested
    class Update {
        private final String currentZoneId = UAA;
        private ScimUser originalUser;
        private ScimUser existingOriginalUser;

        @BeforeEach
        void setUp() {
            arrangeCurrentIdz(currentZoneId);

            final Pair<ScimUser, ScimUser> userAndAlias = buildUserAndAlias(origin, currentZoneId, aliasZid);
            originalUser = userAndAlias.getLeft();
            existingOriginalUser = cloneScimUser(originalUser);
            existingOriginalUser.setVersion(1);
            originalUser.setName(new ScimUser.Name("some-new-given-name", "some-new-family-name"));
            when(scimUserProvisioning.retrieve(originalUser.getId(), currentZoneId)).thenReturn(existingOriginalUser);
        }

        @Test
        void shouldThrow_IfAliasPropertiesAreInvalid() {
            when(scimUserAliasHandler.aliasPropertiesAreValid(originalUser, existingOriginalUser))
                    .thenReturn(false);

            assertThatThrownBy(() ->
                    scimUserEndpoints.updateUser(
                            originalUser,
                            originalUser.getId(),
                            "*",
                            new MockHttpServletRequest(),
                            new MockHttpServletResponse(),
                            null))
                    .isInstanceOf(ScimException.class)
                    .hasMessage("The fields 'aliasId' and/or 'aliasZid' are invalid.")
                    .satisfies(e -> assertThat(((ScimException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        }

        @Test
        void shouldThrow_IfAliasIsLocked() {
            when(scimUserAliasHandler.aliasPropertiesAreValid(originalUser, existingOriginalUser))
                    .thenReturn(true);
            when(transactionTemplate.execute(any())).then(invocationOnMock -> {
                throw new OptimisticLockingFailureException("The alias is locked.");
            });

            assertThatThrownBy(() ->
                    scimUserEndpoints.updateUser(
                            originalUser,
                            originalUser.getId(),
                            "*",
                            new MockHttpServletRequest(),
                            new MockHttpServletResponse(),
                            null
                    ))
                    .isInstanceOf(ScimResourceConflictException.class)
                    .hasMessage("The alias is locked.")
                    .satisfies(e -> assertThat(((ScimResourceConflictException) e).getStatus()).isEqualTo(HttpStatus.CONFLICT));
        }

        @Test
        void shouldAlsoUpdateAliasUserIfPresent() {
            when(scimUserAliasHandler.aliasPropertiesAreValid(originalUser, existingOriginalUser))
                    .thenReturn(true);

            // mock update -> increments version
            when(scimUserProvisioning.update(originalUser.getId(), originalUser, currentZoneId))
                    .then(invocationOnMock -> {
                        final ScimUser user = invocationOnMock.getArgument(1);
                        user.setVersion(user.getVersion() + 1);
                        return user;
                    });

            // mock aliasHandler.ensureConsistency -> no changes to original user
            when(scimUserAliasHandler.ensureConsistencyOfAliasEntity(originalUser, existingOriginalUser))
                    .then(invocationOnMock -> invocationOnMock.getArgument(0));

            final ScimUser result = scimUserEndpoints.updateUser(
                    originalUser,
                    originalUser.getId(),
                    "*",
                    new MockHttpServletRequest(),
                    new MockHttpServletResponse(),
                    null
            );
            assertScimUsersAreEqual(result, originalUser);
        }

        @Test
        void shouldThrowScimException_IfAliasHandlerThrows() {
            when(scimUserAliasHandler.aliasPropertiesAreValid(originalUser, existingOriginalUser))
                    .thenReturn(true);

            // mock update -> increments version
            when(scimUserProvisioning.update(originalUser.getId(), originalUser, currentZoneId))
                    .then(invocationOnMock -> {
                        final ScimUser user = invocationOnMock.getArgument(1);
                        user.setVersion(user.getVersion() + 1);
                        return user;
                    });

            // mock aliasHandler.ensureConsistency -> should throw exception
            final String errorMessage = "Could not create alias.";
            when(scimUserAliasHandler.ensureConsistencyOfAliasEntity(originalUser, existingOriginalUser))
                    .thenThrow(new EntityAliasFailedException(errorMessage, 400, null));

            assertThatThrownBy(() ->
                    scimUserEndpoints.updateUser(
                            originalUser,
                            originalUser.getId(),
                            "*",
                            new MockHttpServletRequest(),
                            new MockHttpServletResponse(),
                            null
                    ))
                    .isInstanceOf(ScimException.class)
                    .hasMessage(errorMessage)
                    .satisfies(e -> assertThat(((ScimException) e).getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        }
    }

    @Nested
    class Delete {
        @BeforeEach
        void setUp() {
            scimUserEndpoints.setApplicationEventPublisher(applicationEventPublisher);
        }

        @Nested
        class AliasFeatureEnabled {
            private ScimUser originalUser;
            private ScimUser aliasUser;

            @BeforeEach
            void setUp() {
                arrangeCurrentIdz(UAA);

                final Pair<ScimUser, ScimUser> userAndAlias = buildUserAndAlias(origin, UAA, aliasZid);
                originalUser = userAndAlias.getLeft();
                originalUser.setVersion(2);
                when(scimUserProvisioning.retrieve(originalUser.getId(), UAA)).thenReturn(originalUser);

                aliasUser = userAndAlias.getRight();
            }

            @Test
            void shouldAlsoDeleteAliasUserIfPresent() {
                when(scimUserAliasHandler.retrieveAliasEntity(originalUser)).thenReturn(Optional.of(aliasUser));

                final ScimUser response = scimUserEndpoints.deleteUser(
                        originalUser.getId(),
                        null,
                        new MockHttpServletRequest(),
                        new MockHttpServletResponse()
                );

                assertScimUsersAreEqual(response, originalUser);

                assertOriginalAndAliasUserAreRemovedFromGroups(originalUser.getId(), UAA, aliasUser.getId(), aliasZid);
                assertOriginalAndAliasUsersAreDeleted(originalUser.getId(), UAA, aliasUser.getId(), aliasZid, aliasUser.getVersion());
                assertEventIsPublishedForOriginalAndAliasUser(UAA, originalUser, aliasZid, aliasUser);
            }

            @Test
            void shouldIgnore_ReferencedAliasUserNotPresent() {
                // arrange referenced alias user is not present
                when(scimUserAliasHandler.retrieveAliasEntity(originalUser)).thenReturn(Optional.empty());

                final ScimUser response = scimUserEndpoints.deleteUser(
                        originalUser.getId(),
                        null,
                        new MockHttpServletRequest(),
                        new MockHttpServletResponse()
                );

                assertScimUsersAreEqual(response, originalUser);

                verify(scimGroupMembershipManager).removeMembersByMemberId(originalUser.getId(), UAA);
                verify(scimUserProvisioning).delete(originalUser.getId(), -1, UAA);
                final ArgumentCaptor<EntityDeletedEvent<ScimUser>> eventArgument = ArgumentCaptor.forClass(EntityDeletedEvent.class);
                verify(applicationEventPublisher).publishEvent(eventArgument.capture());
                final EntityDeletedEvent<ScimUser> capturedEvent = eventArgument.getValue();
                assertThat(capturedEvent.getIdentityZoneId()).isEqualTo(UAA);
                assertScimUsersAreEqual(capturedEvent.getDeleted(), originalUser);
            }

            private void assertOriginalAndAliasUserAreRemovedFromGroups(
                    final String userId,
                    final String zoneId,
                    final String aliasId,
                    final String aliasZid
            ) {
                final ArgumentCaptor<String> memberIdArgument = ArgumentCaptor.forClass(String.class);
                final ArgumentCaptor<String> zoneIdArgument = ArgumentCaptor.forClass(String.class);
                verify(scimGroupMembershipManager, times(2)).removeMembersByMemberId(
                        memberIdArgument.capture(),
                        zoneIdArgument.capture()
                );
                final List<String> capturedMemberIds = memberIdArgument.getAllValues();
                assertThat(capturedMemberIds.getFirst()).isEqualTo(userId);
                assertThat(capturedMemberIds.get(1)).isEqualTo(aliasId);
                final List<String> capturedZoneIds = zoneIdArgument.getAllValues();
                assertThat(capturedZoneIds.getFirst()).isEqualTo(zoneId);
                assertThat(capturedZoneIds.get(1)).isEqualTo(aliasZid);
            }

            private void assertEventIsPublishedForOriginalAndAliasUser(
                    final String zoneId,
                    final ScimUser originalUser,
                    final String aliasZid,
                    final ScimUser aliasUser
            ) {
                final ArgumentCaptor<EntityDeletedEvent<ScimUser>> eventArgument = ArgumentCaptor.forClass(EntityDeletedEvent.class);
                verify(applicationEventPublisher, times(2)).publishEvent(eventArgument.capture());
                final List<EntityDeletedEvent<ScimUser>> capturedEvents = eventArgument.getAllValues();
                final EntityDeletedEvent<ScimUser> eventForOriginalUser = capturedEvents.getFirst();
                assertThat(eventForOriginalUser.getIdentityZoneId()).isEqualTo(zoneId);
                assertScimUsersAreEqual(eventForOriginalUser.getDeleted(), originalUser);
                final EntityDeletedEvent<ScimUser> eventForAliasUser = capturedEvents.get(1);
                assertThat(eventForAliasUser.getIdentityZoneId()).isEqualTo(aliasZid);
                assertScimUsersAreEqual(eventForAliasUser.getDeleted(), aliasUser);
            }

            private void assertOriginalAndAliasUsersAreDeleted(
                    final String userId,
                    final String zoneId,
                    final String aliasId,
                    final String aliasZid,
                    final int aliasUserVersion
            ) {
                final ArgumentCaptor<String> userIdArgument = ArgumentCaptor.forClass(String.class);
                final ArgumentCaptor<Integer> versionArgument = ArgumentCaptor.forClass(Integer.class);
                final ArgumentCaptor<String> zoneIdArgument = ArgumentCaptor.forClass(String.class);
                verify(scimUserProvisioning, times(2)).delete(
                        userIdArgument.capture(),
                        versionArgument.capture(),
                        zoneIdArgument.capture()
                );
                final List<String> capturedUserIds = userIdArgument.getAllValues();
                assertThat(capturedUserIds.getFirst()).isEqualTo(userId);
                assertThat(capturedUserIds.get(1)).isEqualTo(aliasId);
                final List<Integer> capturedVersions = versionArgument.getAllValues();
                assertThat(capturedVersions.getFirst())
                        .isEqualTo(-1); // etag in scimUserEndpoints.deleteUser call is null
                assertThat(capturedVersions.get(1)).isEqualTo(aliasUserVersion);
                final List<String> capturedZoneIds2 = zoneIdArgument.getAllValues();
                assertThat(capturedZoneIds2.getFirst()).isEqualTo(zoneId);
                assertThat(capturedZoneIds2.get(1)).isEqualTo(aliasZid);
            }
        }

        @Nested
        class AliasFeatureDisabled {
            @BeforeEach
            void setUp() {
                arrangeAliasFeatureIsEnabled(false);
            }

            @AfterEach
            void tearDown() {
                arrangeAliasFeatureIsEnabled(true);
            }

            @Test
            void shouldThrowException_IfUserHasExistingAlias() {
                arrangeCurrentIdz(UAA);

                final Pair<ScimUser, ScimUser> userAndAlias = buildUserAndAlias(origin, UAA, aliasZid);
                final ScimUser originalUser = userAndAlias.getLeft();
                originalUser.setVersion(2);
                when(scimUserProvisioning.retrieve(originalUser.getId(), UAA)).thenReturn(originalUser);

                final MockHttpServletRequest req = new MockHttpServletRequest();
                final MockHttpServletResponse res = new MockHttpServletResponse();
                assertThatThrownBy(() -> scimUserEndpoints.deleteUser(originalUser.getId(), null, req, res))
                        .isInstanceOf(UaaException.class)
                        .hasMessage("Could not delete user with alias since alias entities are disabled.")
                        .satisfies(e -> assertThat(((UaaException) e).getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value()));
            }

            @Test
            void shouldDeleteUserIfPresent() {
                ScimUser originalUser = buildScimUser("123456789", "uaa");
                when(scimUserProvisioning.retrieve(any(), any())).thenReturn(originalUser);
                final ScimUser response = scimUserEndpoints.deleteUser(
                        "12345678",
                        null,
                        new MockHttpServletRequest(),
                        new MockHttpServletResponse()
                );

                assertScimUsersAreEqual(response, originalUser);
            }
        }
    }

    private void arrangeAliasFeatureIsEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(scimUserEndpoints, "aliasEntitiesEnabled", enabled);
    }

    /**
     * This method is required because the {@link ScimUser} class does not implement an adequate {@code equals} method.
     */
    private static void assertScimUsersAreEqual(final ScimUser actual, final ScimUser expected) {
        assertThat(actual.getId()).isEqualTo(expected.getId());
        assertThat(actual.getExternalId()).isEqualTo(expected.getExternalId());
        assertThat(actual.getOrigin()).isEqualTo(expected.getOrigin());

        assertThat(actual.getUserName()).isEqualTo(expected.getUserName());
        assertThat(actual.getName()).isEqualTo(expected.getName());

        assertThat(actual.getEmails()).hasSameElementsAs(expected.getEmails());

        assertThat(actual.getZoneId()).isEqualTo(expected.getZoneId());
        assertThat(actual.getAliasId()).isEqualTo(expected.getAliasId());
        assertThat(actual.getAliasZid()).isEqualTo(expected.getAliasZid());

        assertThat(actual.getLastLogonTime()).isEqualTo(expected.getLastLogonTime());
        assertThat(actual.getPreviousLogonTime()).isEqualTo(expected.getPreviousLogonTime());
        assertThat(actual.getPasswordLastModified()).isEqualTo(expected.getPasswordLastModified());

        assertThat(actual.isActive()).isEqualTo(expected.isActive());
        assertThat(actual.isVerified()).isEqualTo(expected.isVerified());
    }

    private static Pair<ScimUser, ScimUser> buildUserAndAlias(
            final String origin,
            final String zoneId,
            final String aliasZid
    ) {
        final ScimUser originalUser = buildScimUser(zoneId, origin);
        final String userId = UUID.randomUUID().toString();
        originalUser.setId(userId);
        originalUser.setAliasZid(aliasZid);
        final String aliasId = UUID.randomUUID().toString();
        originalUser.setAliasId(aliasId);

        final ScimUser aliasUser = buildScimUser(aliasZid, origin);
        aliasUser.setId(aliasId);
        aliasUser.setAliasId(userId);
        aliasUser.setAliasZid(zoneId);

        return Pair.of(originalUser, aliasUser);
    }

    private static ScimUser cloneScimUser(final ScimUser scimUser) {
        final ScimUser clonedScimUser = new ScimUser();
        clonedScimUser.setId(scimUser.getId());
        clonedScimUser.setUserName(scimUser.getUserName());
        clonedScimUser.setPrimaryEmail(scimUser.getPrimaryEmail());
        clonedScimUser.setName(scimUser.getName());
        clonedScimUser.setActive(scimUser.isActive());
        clonedScimUser.setPhoneNumbers(scimUser.getPhoneNumbers());
        clonedScimUser.setOrigin(scimUser.getOrigin());
        clonedScimUser.setAliasId(scimUser.getAliasId());
        clonedScimUser.setAliasZid(scimUser.getAliasZid());
        clonedScimUser.setZoneId(scimUser.getZoneId());
        clonedScimUser.setPassword(scimUser.getPassword());
        clonedScimUser.setSalt(scimUser.getSalt());
        return clonedScimUser;
    }
}
