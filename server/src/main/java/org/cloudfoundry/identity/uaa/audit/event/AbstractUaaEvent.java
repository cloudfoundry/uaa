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

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationDetails;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import tools.jackson.core.type.TypeReference;

import java.io.Serial;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

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

    private static final Logger logger = LoggerFactory.getLogger(AbstractUaaEvent.class);

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

    protected AuditEvent createAuditRecord(String principalId, AuditEventType type, String origin, String data, String principalName) {
        return new AuditEvent(type, principalId, origin, data, System.currentTimeMillis(), zoneId, null, null, principalName);
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

        Object details = caller.getDetails();
        if (details != null) {
            builder.append(", details=(");
            extractRemoteAddress(details).ifPresent(address -> builder.append("remoteAddress=").append(address).append(", "));
            builder.append("type=").append(details.getClass().getSimpleName());
            appendTokenDetails(caller, builder);
            builder.append(")");
        }

        return builder.toString();
    }

    private Optional<String> extractRemoteAddress(Object details) {
        return switch (details) {
            case UaaAuthenticationDetails d -> Optional.ofNullable(d.getOrigin());
            case OAuth2AuthenticationDetails d -> Optional.ofNullable(d.getRemoteAddress());
            case Map<?, ?> map -> Optional.ofNullable(map.get("remoteAddress")).map(Object::toString);
            case String jsonBlob -> extractRemoteAddressFromJson(jsonBlob);
            default -> {
                logger.warn("Unhandled Authentication.details type in audit origin: {}", details.getClass().getName());
                yield Optional.empty();
            }
        };
    }

    private Optional<String> extractRemoteAddressFromJson(String jsonBlob) {
        try {
            Map<String, Object> map = JsonUtils.readValue(jsonBlob, new TypeReference<>() {
            });
            return map == null ? Optional.empty() : extractRemoteAddress(map);
        } catch (JsonUtils.JsonUtilException _) {
            return Optional.empty();
        }
    }

    private void appendTokenDetails(Authentication caller, StringBuilder builder) {
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
                } catch (Exception _) {
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
