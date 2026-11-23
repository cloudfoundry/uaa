package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class ScimUserBootstrapGroupAuditTests {

    private ScimGroupMembershipManager membershipManager;
    private ApplicationEventPublisher publisher;
    private ScimUserBootstrap bootstrap;
    private UaaUser user;

    @BeforeEach
    void setUp() {
        membershipManager = mock(ScimGroupMembershipManager.class);
        publisher = mock(ApplicationEventPublisher.class);
        IdentityZoneManager zoneManager = mock(IdentityZoneManager.class);
        when(zoneManager.getCurrentIdentityZoneId()).thenReturn("tenant");
        user = new UaaUser(new UaaUserPrototype().withId("user").withUsername("user")
                .withEmail("user@example.com").withOrigin("oidc").withZoneId("tenant"));
        bootstrap = new ScimUserBootstrap(null, null, null, membershipManager, zoneManager,
                List.of(), false, List.of(), false);
        bootstrap.setApplicationEventPublisher(publisher);
    }

    @ParameterizedTest
    @ValueSource(strings = {"uaa", "tenant"})
    void removedMembershipPublishesAuditWithRemainingMembersAndGroupZone(String zoneId) {
        ScimGroup group = new ScimGroup("group", "revoked.scope", zoneId);
        when(membershipManager.getGroupsWithExternalMember("user", "oidc", "tenant"))
                .thenReturn(Set.of(group));
        when(membershipManager.getMembers("group", false, zoneId))
                .thenReturn(List.of(new ScimGroupMember("remaining-user"), new ScimGroupMember("nested-group")));

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, List.of(), true));

        var order = inOrder(membershipManager, publisher);
        order.verify(membershipManager).removeMemberById("group", "user", zoneId);
        order.verify(membershipManager).getMembers("group", false, zoneId);
        ArgumentCaptor<ApplicationEvent> captor = ArgumentCaptor.forClass(ApplicationEvent.class);
        order.verify(publisher).publishEvent(captor.capture());
        assertThat(captor.getValue()).isInstanceOfSatisfying(GroupModifiedEvent.class, event -> {
            assertThat(event.getGroupId()).isEqualTo("group");
            assertThat(event.getMembers()).containsExactly("remaining-user", "nested-group");
            assertThat(event.getAuditEvent().getIdentityZoneId()).isEqualTo(zoneId);
            assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.GroupModifiedEvent);
            assertThat(event.getAuditEvent().getData()).contains("revoked.scope").doesNotContain("\"user\"");
        });
        verifyNoMoreInteractions(publisher);
    }

    @Test
    void unchangedMembershipDoesNotPublishAudit() {
        when(membershipManager.getGroupsWithExternalMember("user", "oidc", "tenant"))
                .thenReturn(Set.of(new ScimGroup("group", "retained.scope", "tenant")));

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false,
                AuthorityUtils.createAuthorityList("retained.scope"), true));

        verify(membershipManager, never()).removeMemberById(anyString(), anyString(), anyString());
        verifyNoInteractions(publisher);
    }

    @Test
    void alreadyRemovedMembershipDoesNotPublishAudit() {
        when(membershipManager.getGroupsWithExternalMember("user", "oidc", "tenant"))
                .thenReturn(Set.of(new ScimGroup("group", "revoked.scope", "tenant")));
        when(membershipManager.removeMemberById("group", "user", "tenant"))
                .thenThrow(new MemberNotFoundException("Already removed"));

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, List.of(), true));

        verify(membershipManager, never()).getMembers(anyString(), anyBoolean(), anyString());
        verifyNoInteractions(publisher);
    }

    @Test
    void zeroRowDeleteSkipsAuditAndContinuesReconciliation() {
        ScimGroup alreadyRemoved = new ScimGroup("removed", "removed.scope", "tenant");
        ScimGroup stale = new ScimGroup("stale", "stale.scope", "tenant");
        when(membershipManager.getGroupsWithExternalMember("user", "oidc", "tenant"))
                .thenReturn(new LinkedHashSet<>(List.of(alreadyRemoved, stale)));
        when(membershipManager.removeMemberById("removed", "user", "tenant"))
                .thenThrow(new IncorrectResultSizeDataAccessException(1, 0));

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, List.of(), true));

        verify(membershipManager, never()).getMembers("removed", false, "tenant");
        verify(membershipManager).removeMemberById("stale", "user", "tenant");
        ArgumentCaptor<GroupModifiedEvent> captor = ArgumentCaptor.forClass(GroupModifiedEvent.class);
        verify(publisher).publishEvent(captor.capture());
        assertThat(captor.getValue().getGroupId()).isEqualTo("stale");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void auditFailureAllowsLaterMembershipRemoval(boolean failDuringPublication) {
        ScimGroup first = new ScimGroup("first", "first.scope", "tenant");
        ScimGroup second = new ScimGroup("second", "second.scope", "tenant");
        when(membershipManager.getGroupsWithExternalMember("user", "oidc", "tenant"))
                .thenReturn(new LinkedHashSet<>(List.of(first, second)));
        var failure = new DataAccessResourceFailureException("Audit data unavailable");
        if (failDuringPublication) {
            doThrow(failure).when(publisher)
                    .publishEvent(argThat((GroupModifiedEvent event) -> "first".equals(event.getGroupId())));
        } else {
            when(membershipManager.getMembers("first", false, "tenant")).thenThrow(failure);
        }

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, List.of(), true));

        verify(membershipManager).removeMemberById("first", "user", "tenant");
        verify(membershipManager).removeMemberById("second", "user", "tenant");
        verify(publisher).publishEvent(argThat((GroupModifiedEvent event) -> "second".equals(event.getGroupId())));
    }

    @Test
    void unexpectedDeleteCountStillFailsReconciliation() {
        when(membershipManager.getGroupsWithExternalMember("user", "oidc", "tenant"))
                .thenReturn(Set.of(new ScimGroup("group", "revoked.scope", "tenant")));
        var failure = new IncorrectResultSizeDataAccessException(1, 2);
        when(membershipManager.removeMemberById("group", "user", "tenant")).thenThrow(failure);

        assertThatThrownBy(() -> bootstrap.onApplicationEvent(
                new ExternalGroupAuthorizationEvent(user, false, List.of(), true))).isSameAs(failure);
        verifyNoInteractions(publisher);
    }

    @Test
    void failedRemovalDoesNotPublishAudit() {
        when(membershipManager.getGroupsWithExternalMember("user", "oidc", "tenant"))
                .thenReturn(Set.of(new ScimGroup("group", "revoked.scope", "tenant")));
        when(membershipManager.removeMemberById("group", "user", "tenant"))
                .thenThrow(new IllegalStateException("Database unavailable"));

        assertThatThrownBy(() -> bootstrap.onApplicationEvent(
                new ExternalGroupAuthorizationEvent(user, false, List.of(), true)))
                .isInstanceOf(IllegalStateException.class).hasMessage("Database unavailable");
        verifyNoInteractions(publisher);
    }

    @Test
    void localUserDoesNotReconcileExternalMemberships() {
        user = user.modifyOrigin(OriginKeys.UAA);

        bootstrap.onApplicationEvent(new ExternalGroupAuthorizationEvent(user, false, List.of(), true));

        verifyNoInteractions(membershipManager, publisher);
    }
}
