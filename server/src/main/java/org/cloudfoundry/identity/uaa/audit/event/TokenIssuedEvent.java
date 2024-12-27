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
package org.cloudfoundry.identity.uaa.audit.event;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.core.Authentication;

import java.util.Map;

public class TokenIssuedEvent extends AbstractUaaEvent {


    public TokenIssuedEvent(OAuth2AccessToken source, Authentication principal, String zoneId) {
        super(source, principal, zoneId);
        if (!OAuth2AccessToken.class.isAssignableFrom(source.getClass())) {
            throw new IllegalArgumentException();
        }
    }

    @Override
    public OAuth2AccessToken getSource() {
        return (OAuth2AccessToken) super.getSource();
    }

    @Override
    public AuditEvent getAuditEvent() {
        String data = JsonUtils.writeValueAsString(getSource().getScope());
        return createAuditRecord(getPrincipalId(), AuditEventType.TokenIssuedEvent, getOrigin(getAuthentication()), data);
    }

    private String getPrincipalId() {
        OAuth2AccessToken token = getSource();
        Jwt jwt = JwtHelper.decode(token.getValue());
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        return (claims.get("user_id") != null ? claims.get("user_id") : claims.get("client_id")).toString();
    }
}
