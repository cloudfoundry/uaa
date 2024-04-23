package org.cloudfoundry.identity.uaa.scim.endpoints;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.util.StringUtils.hasText;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.apache.commons.lang3.tuple.Pair;
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
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;

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
    private PlatformTransactionManager platformTransactionManager;
    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    private ScimUserEndpoints scimUserEndpoints;
    private String idzId;
    private String origin;

    @BeforeEach
    void setUp() {
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
                scimUserAliasHandler,
                platformTransactionManager,
                false,
                500
        );

        idzId = RANDOM_STRING_GENERATOR.generate();
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
            final ScimException exception = assertThrows(ScimException.class, () ->
                    scimUserEndpoints.createUser(user, req, res)
            );
            assertThat(exception.getMessage()).isEqualTo("Alias ID and/or alias ZID are invalid.");
            assertThat(exception.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
        }

        @Test
        void shouldReturnOriginalUser() {
            final ScimUser user = buildScimUser(UAA, origin);
            user.setAliasZid(UUID.randomUUID().toString());

            when(scimUserAliasHandler.aliasPropertiesAreValid(user, null)).thenReturn(true);

            final ScimUser response = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
            assertThat(response.getAliasId()).isNotBlank();
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
            @BeforeEach
            void setUp() {
                ReflectionTestUtils.setField(scimUserEndpoints, "aliasEntitiesEnabled", true);
            }

            @AfterEach
            void tearDown() {
                ReflectionTestUtils.setField(scimUserEndpoints, "aliasEntitiesEnabled", false);
            }

            @Test
            void shouldAlsoDeleteAliasUserIfPresent() {
                arrangeCurrentIdz(UAA);

                final String aliasZid = UUID.randomUUID().toString();
                final Pair<ScimUser, ScimUser> userAndAlias = buildUserAndAlias(origin, UAA, aliasZid);

                final ScimUser originalUser = userAndAlias.getLeft();
                originalUser.setVersion(2);
                when(scimUserProvisioning.retrieve(originalUser.getId(), UAA)).thenReturn(originalUser);

                final ScimUser aliasUser = userAndAlias.getRight();
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
                assertThat(capturedMemberIds.get(0)).isEqualTo(userId);
                assertThat(capturedMemberIds.get(1)).isEqualTo(aliasId);
                final List<String> capturedZoneIds = zoneIdArgument.getAllValues();
                assertThat(capturedZoneIds.get(0)).isEqualTo(zoneId);
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
                final EntityDeletedEvent<ScimUser> eventForOriginalUser = capturedEvents.get(0);
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
                assertThat(capturedUserIds.get(0)).isEqualTo(userId);
                assertThat(capturedUserIds.get(1)).isEqualTo(aliasId);
                final List<Integer> capturedVersions = versionArgument.getAllValues();
                assertThat(capturedVersions.get(0))
                        .isEqualTo(-1); // etag in scimUserEndpoints.deleteUser call is null
                assertThat(capturedVersions.get(1)).isEqualTo(aliasUserVersion);
                final List<String> capturedZoneIds2 = zoneIdArgument.getAllValues();
                assertThat(capturedZoneIds2.get(0)).isEqualTo(zoneId);
                assertThat(capturedZoneIds2.get(1)).isEqualTo(aliasZid);
            }
        }

        @Nested
        class AliasFeatureDisabled {
            @Test
            void shouldThrowException_IfUserHasExistingAlias() {
                arrangeCurrentIdz(UAA);

                final Pair<ScimUser, ScimUser> userAndAlias = buildUserAndAlias(origin, UAA, idzId);
                final ScimUser originalUser = userAndAlias.getLeft();
                originalUser.setVersion(2);
                when(scimUserProvisioning.retrieve(originalUser.getId(), UAA)).thenReturn(originalUser);

                final MockHttpServletRequest req = new MockHttpServletRequest();
                final MockHttpServletResponse res = new MockHttpServletResponse();
                final UaaException exception = assertThrows(UaaException.class, () ->
                        scimUserEndpoints.deleteUser(originalUser.getId(), null, req, res)
                );
                assertThat(exception.getMessage())
                        .isEqualTo("Could not delete user with alias since alias entities are disabled.");
                assertThat(exception.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
            }
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
}
