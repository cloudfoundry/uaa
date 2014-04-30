/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;

public class TokenIssuedEvent extends AbstractUaaEvent {

    private ObjectMapper mapper = new ObjectMapper();

    public TokenIssuedEvent(OAuth2AccessToken source, Authentication principal) {
        super(source, principal);
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
        String data = null;
        try {
            data = mapper.writeValueAsString(getSource().getScope());
        } catch (IOException e) { }
        return createAuditRecord(getPrincipalId(), AuditEventType.TokenIssuedEvent, getOrigin(getAuthentication()), data);
    }

    private String getPrincipalId() {
        OAuth2AccessToken token = getSource();
        Jwt jwt = JwtHelper.decode(token.getValue());
        try {
            Map<String, Object> claims = mapper.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {});
            return (claims.get("user_id") != null ? claims.get("user_id") : claims.get("client_id")).toString();
        } catch (IOException e) {
            return null;
        }
    }
}
