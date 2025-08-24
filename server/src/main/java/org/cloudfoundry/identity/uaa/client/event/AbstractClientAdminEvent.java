/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.client.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public abstract class AbstractClientAdminEvent extends AbstractUaaEvent {

    private final ClientDetails nonExistent = new UaaClientDetails("non-existent", "", "", "", "");

    private final ClientDetails client;

    public AbstractClientAdminEvent(ClientDetails client, Authentication principal, String zoneId) {
        super(principal, zoneId);
        this.client = client;
    }

    ClientDetails getClient() {
        return client;
    }

    Principal getPrincipal() {
        return getAuthentication();
    }

    abstract AuditEventType getAuditEventType();

    @Override
    public AuditEvent getAuditEvent() {
        ClientDetails clientDetails = Optional.ofNullable(getClient()).orElse(nonExistent);
        Map<String, Object> auditData = new HashMap();
        auditData.put("scopes", clientDetails.getScope());
        List<String> authorities =
                clientDetails
                        .getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();
        auditData.put("authorities", authorities);
        return createAuditRecord(
                clientDetails.getClientId(),
                getAuditEventType(),
                getOrigin(getPrincipal()),
                JsonUtils.writeValueAsString(auditData)
        );
    }

}
