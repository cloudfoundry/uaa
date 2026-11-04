package org.cloudfoundry.identity.uaa.scim.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataAccessResourceFailureException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimMembershipEventPublisherTests {
    @Mock private IdentityZoneManager zoneManager;
    @Mock private ScimUserProvisioning users;
    @Mock private ScimGroupProvisioning groups;
    @Mock private ApplicationEventPublisher events;
    private ScimEventPublisher publisher;

    @BeforeEach
    void setUp() {
        when(zoneManager.getCurrentIdentityZoneId()).thenReturn("tenant-zone");
        publisher = new ScimEventPublisher(zoneManager, users, groups);
        publisher.setApplicationEventPublisher(events);
    }

    @Test
    void resolvesOnlyChangedMembersInCurrentZoneBeforePublishing() {
        ScimGroup before = group(List.of(new ScimGroupMember("removed"), new ScimGroupMember("retained")));
        ScimGroup after = group(List.of(new ScimGroupMember("retained"), new ScimGroupMember("added")));
        when(users.retrieve("removed", "tenant-zone")).thenReturn(user("old-user"));
        when(users.retrieve("added", "tenant-zone")).thenReturn(user("new-user"));

        List<GroupMembershipEvent> prepared = publisher.prepareMembershipChanges(before, after);

        verifyNoInteractions(events);
        verify(users, never()).retrieve("retained", "tenant-zone");
        assertThat(prepared).extracting(event -> event.getAuditEvent().getType())
                .containsExactly(AuditEventType.GroupMembershipRemovedEvent, AuditEventType.GroupMembershipAddedEvent);
        assertThat(prepared).allSatisfy(event -> assertThat(event.getAuditEvent().getIdentityZoneId()).isEqualTo("tenant-zone"));
        assertThat(JsonUtils.readValueAsMap(prepared.getFirst().getAuditEvent().getData()))
                .containsExactlyInAnyOrderEntriesOf(Map.of("group_name", "group", "member_id", "removed",
                        "member_name", "old-user", "member_type", "USER"));
        prepared.forEach(publisher::publishMembershipEvent);
        verify(events).publishEvent(prepared.getFirst());
        verify(events).publishEvent(prepared.getLast());
    }

    @Test
    void publishesOnlyPreparedChangesPresentInPersistedResult() {
        when(users.retrieve("added", "tenant-zone")).thenReturn(user("new-user"));
        ScimGroup before = group(List.of());
        List<GroupMembershipEvent> prepared = publisher.prepareMembershipChanges(before,
                group(List.of(new ScimGroupMember("added"))));

        publisher.publishMembershipChanges(prepared, before, before);

        verifyNoInteractions(events);
    }

    @Test
    void unchangedMembershipDoesNotResolveNames() {
        ScimGroup group = group(List.of(new ScimGroupMember("retained")));
        assertThat(publisher.prepareMembershipChanges(group, group)).isEmpty();
        verifyNoInteractions(users, groups, events);
    }

    @Test
    void resolvesNestedGroupDisplayName() {
        when(groups.retrieve("nested", "tenant-zone")).thenReturn(new ScimGroup("nested", "nested-name", "tenant-zone"));
        GroupMembershipEvent event = publisher.prepareMembershipEvent(group(List.of()),
                new ScimGroupMember("nested", ScimGroupMember.Type.GROUP), AuditEventType.GroupMembershipAddedEvent);
        assertThat(JsonUtils.readValueAsMap(event.getAuditEvent().getData()))
                .containsEntry("member_name", "nested-name").containsEntry("member_type", "GROUP");
        verifyNoInteractions(users);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void unavailableNameRetainsIdAndEvent(boolean deleted) {
        when(users.retrieve("member", "tenant-zone")).thenThrow(deleted
                ? new ScimResourceNotFoundException("deleted") : new DataAccessResourceFailureException("unavailable"));
        GroupMembershipEvent event = publisher.prepareMembershipEvent(group(List.of()),
                new ScimGroupMember("member"), AuditEventType.GroupMembershipRemovedEvent);
        assertThat(JsonUtils.readValueAsMap(event.getAuditEvent().getData()))
                .containsEntry("member_id", "member").doesNotContainKey("member_name");
        publisher.publishMembershipEvent(event);
        verify(events).publishEvent(event);
    }

    private static ScimGroup group(List<ScimGroupMember> members) {
        ScimGroup group = new ScimGroup("group-id", "group", "tenant-zone");
        group.setMembers(members);
        return group;
    }

    private static ScimUser user(String name) {
        ScimUser user = new ScimUser();
        user.setUserName(name);
        return user;
    }
}
