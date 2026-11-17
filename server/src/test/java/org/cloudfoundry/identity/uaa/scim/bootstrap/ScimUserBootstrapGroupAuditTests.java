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
import org.springframework.security.core.authority.AuthorityUtils;

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
