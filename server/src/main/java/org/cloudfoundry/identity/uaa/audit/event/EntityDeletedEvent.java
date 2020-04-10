package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;

import static java.util.Optional.ofNullable;

public class EntityDeletedEvent<T> extends AbstractUaaEvent {

    private static final String dataFormat = "Class:%s; ID:%s";

    public EntityDeletedEvent(T deleted, Authentication authentication, String zoneId) {
        super(deleted, authentication, zoneId);
    }

    public T getDeleted() {
        return (T) source;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(
                getAuthentication().getName(),
                AuditEventType.EntityDeletedEvent,
                getOrigin(getAuthentication()),
                String.format(dataFormat, source.getClass().getName(), getObjectId())
        );
    }

    public String getObjectId() {
        Method m = ofNullable(ReflectionUtils.findMethod(source.getClass(), "getId"))
                .orElseGet(() -> ReflectionUtils.findMethod(source.getClass(), "getClientId"));
        return m != null ? (String) ReflectionUtils.invokeMethod(m, source) : String.valueOf(System.identityHashCode(source));
    }
}
