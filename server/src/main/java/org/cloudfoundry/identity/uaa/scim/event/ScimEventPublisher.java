package org.cloudfoundry.identity.uaa.scim.event;

import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import java.util.Collections;

import static java.util.Optional.ofNullable;

public class ScimEventPublisher implements ApplicationEventPublisherAware {

    private final IdentityZoneManager identityZoneManager;

    public ScimEventPublisher(final IdentityZoneManager identityZoneManager) {
        this.identityZoneManager = identityZoneManager;
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

    public void groupDeleted(final ScimGroup group) {
        publish(GroupModifiedEvent.groupDeleted(
                group.getId(),
                group.getDisplayName(),
                getMembers(group),
                identityZoneManager.getCurrentIdentityZoneId()));
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
