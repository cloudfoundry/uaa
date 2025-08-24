package org.cloudfoundry.identity.uaa.scim.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.io.Serial;

public final class UserModifiedEvent extends AbstractUaaEvent {

    @Serial
    private static final long serialVersionUID = 8139998613071093676L;
    private final ScimUser scimUser;
    private final AuditEventType eventType;

    private UserModifiedEvent(
            final ScimUser scimUser,
            final AuditEventType eventType,
            final String zoneId) {
        super(getContextAuthentication(), zoneId);
        this.scimUser = scimUser;
        this.eventType = eventType;
    }

    static UserModifiedEvent userCreated(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserCreatedEvent, zoneId);
    }

    static UserModifiedEvent userModified(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserModifiedEvent, zoneId);
    }

    static UserModifiedEvent userDeleted(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserDeletedEvent, zoneId);
    }

    static UserModifiedEvent userVerified(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserVerifiedEvent, zoneId);
    }

    public static UserModifiedEvent emailChanged(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.EmailChangedEvent, zoneId);
    }

    @Override
    public AuditEvent getAuditEvent() {
        String data = JsonUtils.writeValueAsString(buildDetails());
        return createAuditRecord(
                scimUser.getId(),
                eventType,
                getOrigin(getAuthentication()),
                data);
    }

    private String[] buildDetails() {
        return new String[]{
                "user_id=" + scimUser.getId(),
                "username=" + scimUser.getUserName()
        };
    }

    public String getUserId() {
        return scimUser.getId();
    }

    public String getUsername() {
        return scimUser.getUserName();
    }

    public String getEmail() {
        return scimUser.getPrimaryEmail();
    }

}
