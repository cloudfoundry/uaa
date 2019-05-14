package org.cloudfoundry.identity.uaa.scim.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

public class UserModifiedEvent extends AbstractUaaEvent {

    private static final long serialVersionUID = 8139998613071093676L;
    private final ScimUser scimUser;
    private final AuditEventType eventType;

    private UserModifiedEvent(ScimUser scimUser, AuditEventType eventType) {
        super(getContextAuthentication(), IdentityZoneHolder.getCurrentZoneId());
        this.scimUser = scimUser;
        this.eventType = eventType;
    }

    static UserModifiedEvent userCreated(ScimUser scimUser) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserCreatedEvent);
    }

    static UserModifiedEvent userModified(ScimUser scimUser) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserModifiedEvent);
    }

    static UserModifiedEvent userDeleted(ScimUser scimUser) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserDeletedEvent);
    }

    static UserModifiedEvent userVerified(ScimUser scimUser) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserVerifiedEvent);
    }

    public static UserModifiedEvent emailChanged(ScimUser scimUser) {
        return new UserModifiedEvent(scimUser, AuditEventType.EmailChangedEvent);
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
        if (AuditEventType.UserCreatedEvent.equals(this.eventType)) {

            // Not authenticated, e.g. when saml login creates a shadow user
            if (!getContextAuthentication().isAuthenticated()) {
                return new String[]{
                        "user_id=" + scimUser.getId(),
                        "username=" + scimUser.getUserName(),
                        "user_origin=" + scimUser.getOrigin()
                };
            }

            // Authenticated as a user
            if (getContextAuthentication().getPrincipal() instanceof UaaPrincipal) {
                UaaPrincipal uaaPrincipal = (UaaPrincipal) getContextAuthentication().getPrincipal();

                return new String[]{
                        "user_id=" + scimUser.getId(),
                        "username=" + scimUser.getUserName(),
                        "user_origin=" + scimUser.getOrigin(),
                        "created_by_user_id=" + uaaPrincipal.getId(),
                        "created_by_username=" + uaaPrincipal.getName()
                };
            }

            // Authenticated as a client
            return new String[]{
                    "user_id=" + scimUser.getId(),
                    "username=" + scimUser.getUserName(),
                    "user_origin=" + scimUser.getOrigin(),
                    "created_by_client_id=" + getContextAuthentication().getPrincipal()
            };
        }
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
