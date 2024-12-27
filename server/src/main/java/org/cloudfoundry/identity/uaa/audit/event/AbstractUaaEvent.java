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
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationDetails;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serial;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.isJwtToken;
import static org.springframework.util.StringUtils.hasText;

/**
 * Base class for UAA events that want to publish audit records.
 *
 * @author Luke Taylor
 * @author Dave Syer
 *
 */
public abstract class AbstractUaaEvent extends ApplicationEvent {

    @Serial
    private static final long serialVersionUID = -7639844193401892160L;
    private final transient String zoneId;

    private Authentication authentication;

    protected AbstractUaaEvent(Object source, String zoneId) {
        super(source);
        if (source instanceof Authentication authenticationSource) {
            this.authentication = authenticationSource;
        }
        this.zoneId = zoneId;
    }

    protected AbstractUaaEvent(Object source, Authentication authentication, String zoneId) {
        super(source);
        this.authentication = authentication;
        this.zoneId = zoneId;
    }

    public void process(UaaAuditService auditor) {
        auditor.log(getAuditEvent(), getAuditEvent().getIdentityZoneId());
    }

    protected AuditEvent createAuditRecord(String principalId, AuditEventType type, String origin) {
        return new AuditEvent(type, principalId, origin, null, System.currentTimeMillis(), zoneId, null, null);
    }

    protected AuditEvent createAuditRecord(String principalId, AuditEventType type, String origin, String data) {
        return new AuditEvent(type, principalId, origin, data, System.currentTimeMillis(), zoneId, null, null);
    }

    protected AuditEvent createAuditRecord(String principalId, AuditEventType type, String origin, String data, String authenticationType, String message) {
        return new AuditEvent(type, principalId, origin, data, System.currentTimeMillis(), zoneId, authenticationType, message);
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    // Ideally we want to get to the point where details is never null, but this
    // isn't currently possible
    // due to some OAuth authentication scenarios which don't set it.
    protected String getOrigin(Principal principal) {

        if (principal instanceof Authentication caller) {
            return getAuthenticationString(caller);
        }

        return principal == null ? null : principal.getName();

    }

    private String getAuthenticationString(Authentication caller) {
        StringBuilder builder = new StringBuilder();
        if (caller instanceof OAuth2Authentication oAuth2Authentication) {
            builder.append("client=").append(oAuth2Authentication.getOAuth2Request().getClientId());
            if (!oAuth2Authentication.isClientOnly()) {
                builder.append(", ").append("user=").append(oAuth2Authentication.getName());
            }
        } else {
            builder.append("caller=").append(caller.getName());
        }

        if (caller.getDetails() != null) {
            builder.append(", details=(");
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> map =
                        JsonUtils.readValue((String) caller.getDetails(), new TypeReference<Map<String, Object>>(){
                        });
                if (map.containsKey("remoteAddress")) {
                    builder.append("remoteAddress=").append(map.get("remoteAddress")).append(", ");
                }
                builder.append("type=").append(caller.getDetails().getClass().getSimpleName());
            } catch (Exception e) {
                // ignore
                builder.append(caller.getDetails());
            }
            appendTokenDetails(caller, builder);
            builder.append(")");
        }
        return builder.toString();
    }

    protected void appendTokenDetails(Authentication caller, StringBuilder builder) {
        String tokenValue = null;
        if (caller instanceof UaaOauth2Authentication uaaOauth2Authentication) {
            tokenValue = uaaOauth2Authentication.getTokenValue();
        } else if (caller.getDetails() instanceof OAuth2AuthenticationDetails oAuth2AuthenticationDetails) {
            tokenValue = oAuth2AuthenticationDetails.getTokenValue();
        }
        if (hasText(tokenValue)) {
            if (isJwtToken(tokenValue)) {
                try {
                    Jwt token = JwtHelper.decode(tokenValue);
                    Map<String, Object> claims = JsonUtils.readValue(token.getClaims(), new TypeReference<Map<String, Object>>() {
                    });
                    String issuer = claims.get(ClaimConstants.ISS).toString();
                    String subject = claims.get(ClaimConstants.SUB).toString();
                    builder.append(", sub=").append(subject).append(", ").append("iss=").append(issuer);
                } catch (Exception e) {
                    builder.append(", <token extraction failed>");
                }
            } else {
                builder.append(", opaque-token=present");
            }
        }
    }

    public abstract AuditEvent getAuditEvent();

    protected static Authentication getContextAuthentication() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a == null) {
            a = new Authentication() {

                @Serial
                private static final long serialVersionUID = -6219210214210936383L;
                ArrayList<GrantedAuthority> authorities = new ArrayList<>(0);

                @Override
                public Collection<? extends GrantedAuthority> getAuthorities() {
                    return authorities;
                }

                @Override
                public Object getCredentials() {
                    return null;
                }

                @Override
                public Object getDetails() {
                    return null;
                }

                @Override
                public Object getPrincipal() {
                    return "null";
                }

                @Override
                public boolean isAuthenticated() {
                    return false;
                }

                @Override
                public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
                    // ignore
                }

                @Override
                public String getName() {
                    return "null";
                }
            };
        }
        return a;
    }

    public String getIdentityZoneId() {
        return zoneId;
    }

}
