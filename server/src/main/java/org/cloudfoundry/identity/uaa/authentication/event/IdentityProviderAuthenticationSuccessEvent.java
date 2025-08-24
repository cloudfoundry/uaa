/*
 *  Cloud Foundry
 *  Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *  <p/>
 *  This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  You may not use this product except in compliance with the License.
 *  <p/>
 *  This product includes a number of subcomponents with
 *  separate copyright notices and license terms. Your use of these
 *  subcomponents is subject to the terms and conditions of the
 *  subcomponent's license, as noted in the LICENSE file
 */

package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class IdentityProviderAuthenticationSuccessEvent extends AbstractUaaAuthenticationEvent {
    private final UaaUser user;
    private final String authenticationType;

    public IdentityProviderAuthenticationSuccessEvent(UaaUser user, Authentication authentication, String authenticationType, String zoneId) {
        super(authentication, zoneId);
        this.user = user;
        this.authenticationType = authenticationType;
    }

    @Override
    public AuditEvent getAuditEvent() {
        Assert.notNull(user, "UaaUser cannot be null");
        return createAuditRecord(user.getId(), AuditEventType.IdentityProviderAuthenticationSuccess,
                getOrigin(getAuthenticationDetails()), user.getUsername(), authenticationType, null);
    }

    public UaaUser getUser() {
        return user;
    }

    public String getAuthenticationType() {
        return authenticationType;
    }

}
