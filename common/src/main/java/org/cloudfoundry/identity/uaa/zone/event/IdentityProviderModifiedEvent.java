/*******************************************************************************
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
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.springframework.security.core.Authentication;

public class IdentityProviderModifiedEvent extends AbstractUaaEvent {

    private static final long serialVersionUID = -4559543713244231262L;

    private AuditEventType eventType;

    public IdentityProviderModifiedEvent(IdentityProvider identityProvider, Authentication authentication, AuditEventType type) {
        super(identityProvider, authentication);
        eventType = type;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(getSource().toString(), eventType, getOrigin(getAuthentication()), JsonUtils.writeValueAsString(source));
    }
    
    public static IdentityProviderModifiedEvent identityProviderCreated(IdentityProvider identityProvider) {
        return new IdentityProviderModifiedEvent(identityProvider, getContextAuthentication(), AuditEventType.IdentityProviderCreatedEvent);
    }
    
    public static IdentityProviderModifiedEvent identityProviderModified(IdentityProvider identityProvider) {
        return new IdentityProviderModifiedEvent(identityProvider, getContextAuthentication(), AuditEventType.IdentityProviderModifiedEvent);
    }

}
