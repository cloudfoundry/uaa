package org.cloudfoundry.identity.uaa.events;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationEvent;

/**
 * Event published when user attributes change
 * This event is processed asynchronously to publish SNS notifications
 */
public class UserAttributeChangedEvent extends ApplicationEvent {

    private final UaaUser existingUser;
    private final UaaUser updatedUser;

    public UserAttributeChangedEvent(Object source, UaaUser existingUser, UaaUser updatedUser) {
        super(source);
        this.existingUser = existingUser;
        this.updatedUser = updatedUser;
    }

    public UaaUser getExistingUser() {
        return existingUser;
    }

    public UaaUser getUpdatedUser() {
        return updatedUser;
    }

    @Override
    public String toString() {
        return "UserAttributeChangedEvent{" +
                "userId=" + (updatedUser != null ? updatedUser.getId() : "null") +
                '}';
    }
}
