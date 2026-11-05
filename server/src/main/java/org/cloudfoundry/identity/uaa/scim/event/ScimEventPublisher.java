package org.cloudfoundry.identity.uaa.scim.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;

public class ScimEventPublisher implements ApplicationEventPublisherAware {

    private final IdentityZoneManager identityZoneManager;

    private final ScimUserProvisioning userProvisioning;
    private final ScimGroupProvisioning groupProvisioning;

    public ScimEventPublisher(final IdentityZoneManager identityZoneManager,
            final ScimUserProvisioning userProvisioning, final ScimGroupProvisioning groupProvisioning) {
        this.identityZoneManager = identityZoneManager;
        this.userProvisioning = userProvisioning;
        this.groupProvisioning = groupProvisioning;
    }

    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void userCreated(final ScimUser user) {
        publish(UserModifiedEvent.userCreated(user, identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void userVerified(final ScimUser user) {
        publish(UserModifiedEvent.userVerified(user, identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void userModified(final ScimUser user) {
        publish(UserModifiedEvent.userModified(user, identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void userDeleted(final ScimUser user) {
        publish(UserModifiedEvent.userDeleted(user, identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void groupCreated(final ScimGroup group) {
        publish(GroupModifiedEvent.groupCreated(
                group.getId(),
                group.getDisplayName(),
                getMembers(group),
                identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void groupModified(final ScimGroup group) {
        publish(GroupModifiedEvent.groupModified(
                group.getId(),
                group.getDisplayName(),
                getMembers(group),
                identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void groupModifiedAfterCommit(final ScimGroup group) {
        publishAfterCommit(GroupModifiedEvent.groupModified(group.getId(), group.getDisplayName(),
                getMembers(group), identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void groupDeleted(final ScimGroup group) {
        publish(GroupModifiedEvent.groupDeleted(
                group.getId(),
                group.getDisplayName(),
                getMembers(group),
                identityZoneManager.getCurrentIdentityZoneId()));
    }

    public List<GroupMembershipEvent> prepareMembershipChanges(ScimGroup existing, ScimGroup requested) {
        List<ScimGroupMember> before = ofNullable(existing.getMembers()).orElse(Collections.emptyList());
        List<ScimGroupMember> after = ofNullable(requested.getMembers()).orElse(Collections.emptyList());
        Set<String> beforeIds = memberIds(before);
        Set<String> afterIds = memberIds(after);
        ScimGroup group = new ScimGroup(existing.getId(), requested.getDisplayName(),
                identityZoneManager.getCurrentIdentityZoneId());
        List<GroupMembershipEvent> events = new ArrayList<>();
        before.stream().filter(member -> !afterIds.contains(member.getMemberId()))
                .map(member -> prepareMembershipEvent(group, member, AuditEventType.GroupMembershipRemovedEvent))
                .forEach(events::add);
        after.stream().filter(member -> !beforeIds.contains(member.getMemberId()))
                .map(member -> prepareMembershipEvent(group, member, AuditEventType.GroupMembershipAddedEvent))
                .forEach(events::add);
        return events;
    }

    public GroupMembershipEvent prepareMembershipEvent(ScimGroup group, ScimGroupMember member, AuditEventType type) {
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        String name;
        try {
            name = member.getType() == ScimGroupMember.Type.GROUP
                    ? groupProvisioning.retrieve(member.getMemberId(), zoneId).getDisplayName()
                    : userProvisioning.retrieve(member.getMemberId(), zoneId).getUserName();
        } catch (ScimResourceNotFoundException | DataAccessException ignored) {
            // Enrichment must not prevent the membership operation or its ID-based audit event.
            name = null;
        }
        return new GroupMembershipEvent(group, member, name, type, zoneId);
    }

    public void publishMembershipChanges(List<GroupMembershipEvent> events, ScimGroup before, ScimGroup after) {
        Set<String> beforeIds = memberIds(ofNullable(before.getMembers()).orElse(Collections.emptyList()));
        Set<String> afterIds = memberIds(ofNullable(after.getMembers()).orElse(Collections.emptyList()));
        events.stream().filter(event -> event.describesChange(beforeIds, afterIds)).forEach(this::publishMembershipEvent);
    }

    public void publishMembershipEvent(GroupMembershipEvent event) {
        publishAfterCommit(event);
    }

    private void publishAfterCommit(ApplicationEvent event) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    publish(event);
                }
            });
        } else {
            publish(event);
        }
    }

    private static Set<String> memberIds(List<ScimGroupMember> members) {
        return members.stream().map(ScimGroupMember::getMemberId).collect(Collectors.toSet());
    }

    private static String[] getMembers(final ScimGroup group) {
        return ofNullable(group.getMembers())
                .orElse(Collections.emptyList())
                .stream()
                .map(ScimGroupMember::getMemberId)
                .toArray(String[]::new);
    }

    private void publish(final ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }
}
