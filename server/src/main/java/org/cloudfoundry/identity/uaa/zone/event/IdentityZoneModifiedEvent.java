/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;

import java.io.Serial;

public class IdentityZoneModifiedEvent extends AbstractUaaEvent {

    @Serial
    private static final long serialVersionUID = 562117195472169825L;

    private final AuditEventType eventType;

    protected static final String dataFormat = "id=%s; subdomain=%s";

    public IdentityZoneModifiedEvent(IdentityZone identityZone, Authentication authentication, AuditEventType type, String zoneId) {
        super(identityZone, authentication, zoneId);
        eventType = type;
    }

    @Override
    public AuditEvent getAuditEvent() {
        IdentityZone zone = (IdentityZone) source;
        return createAuditRecord(
                getSource().toString(),
                eventType,
                getOrigin(getAuthentication()),
                IdentityZoneModifiedEvent.dataFormat.formatted(
                        zone.getId(),
                        zone.getSubdomain())
        );
    }

    public static IdentityZoneModifiedEvent identityZoneCreated(IdentityZone identityZone) {
        return new IdentityZoneModifiedEvent(identityZone, getContextAuthentication(),
                AuditEventType.IdentityZoneCreatedEvent, IdentityZoneHolder.getCurrentZoneId());
    }

    public static IdentityZoneModifiedEvent identityZoneModified(IdentityZone identityZone) {
        return new IdentityZoneModifiedEvent(identityZone, getContextAuthentication(),
                AuditEventType.IdentityZoneModifiedEvent, IdentityZoneHolder.getCurrentZoneId());
    }

    public AuditEventType getEventType() {
        return eventType;
    }
}
