/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;

public class ClientAuthenticationSuccessEvent extends AbstractUaaAuthenticationEvent{

    private String clientId;

    public ClientAuthenticationSuccessEvent(Authentication authentication) {
        super(authentication);
        clientId = getAuthenticationDetails().getClientId();
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(clientId, AuditEventType.ClientAuthenticationSuccess,
                getOrigin(getAuthenticationDetails()), "Client authentication success");
    }

    public String getClientId() {
        return clientId;
    }
}
