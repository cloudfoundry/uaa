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
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.springframework.security.core.Authentication;

import java.io.Serial;

public class IdentityProviderModifiedEvent extends AbstractUaaEvent {

    @Serial
    private static final long serialVersionUID = -4559543713244231262L;

    private final AuditEventType eventType;

    protected static final String dataFormat = "id=%s; type=%s; origin=%s; zone=%s";

    IdentityProviderModifiedEvent(IdentityProvider identityProvider, Authentication authentication, AuditEventType type, String zoneId) {
        super(identityProvider, authentication, zoneId);
        eventType = type;
    }

    @Override
    public AuditEvent getAuditEvent() {
        IdentityProvider provider = (IdentityProvider) source;
        return createAuditRecord(getSource().toString(),
                eventType,
                getOrigin(getAuthentication()),
                IdentityProviderModifiedEvent.dataFormat.formatted(
                        provider.getId(),
                        provider.getType(),
                        provider.getOriginKey(),
                        provider.getIdentityZoneId())
        );
    }

    public static IdentityProviderModifiedEvent identityProviderCreated(IdentityProvider identityProvider, String zoneId) {
        return new IdentityProviderModifiedEvent(identityProvider, getContextAuthentication(), AuditEventType.IdentityProviderCreatedEvent, zoneId);
    }

    public static IdentityProviderModifiedEvent identityProviderModified(IdentityProvider identityProvider, String zoneId) {
        return new IdentityProviderModifiedEvent(identityProvider, getContextAuthentication(), AuditEventType.IdentityProviderModifiedEvent, zoneId);
    }

}
