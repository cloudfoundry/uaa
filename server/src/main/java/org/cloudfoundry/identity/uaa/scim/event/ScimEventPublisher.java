package org.cloudfoundry.identity.uaa.scim.event;

import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import java.util.Collections;

import static java.util.Optional.ofNullable;

public class ScimEventPublisher implements ApplicationEventPublisherAware {
    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void userCreated(final ScimUser user) {
        publish(UserModifiedEvent.userCreated(user));
    }

    public void userVerified(final ScimUser user) {
        publish(UserModifiedEvent.userVerified(user));
    }

    public void userModified(final ScimUser user) {
        publish(UserModifiedEvent.userModified(user));
    }

    public void userDeleted(final ScimUser user) {
        publish(UserModifiedEvent.userDeleted(user));
    }

    public void groupCreated(final ScimGroup group) {
        publish(GroupModifiedEvent.groupCreated(
                group.getId(),
                group.getDisplayName(),
                getMembers(group),
                IdentityZoneHolder.getCurrentZoneId()));
    }

    public void groupModified(final ScimGroup group) {
        publish(GroupModifiedEvent.groupModified(
                group.getId(),
                group.getDisplayName(),
                getMembers(group),
                IdentityZoneHolder.getCurrentZoneId()));
    }

    public void groupDeleted(final ScimGroup group) {
        publish(GroupModifiedEvent.groupDeleted(
                group.getId(),
                group.getDisplayName(),
                getMembers(group),
                IdentityZoneHolder.getCurrentZoneId()));
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
