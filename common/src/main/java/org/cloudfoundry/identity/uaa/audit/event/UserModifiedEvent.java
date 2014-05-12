/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class UserModifiedEvent extends AbstractUaaEvent {

    private String userId;
    private String username;
    private AuditEventType eventType;

    protected UserModifiedEvent(String userId, String username, AuditEventType type, Authentication authentication) {
        super(authentication);
        this.userId = userId;
        this.username = username;
        this.eventType = type;
    }

    public static UserModifiedEvent userCreated(String userId, String username) {
        return new UserModifiedEvent(
            userId,
            username,
            AuditEventType.UserCreatedEvent,
            getContextAuthentication());
    }

    public static UserModifiedEvent userModified(String userId, String username) {
        return new UserModifiedEvent(
            userId,
            username,
            AuditEventType.UserModifiedEvent,
            getContextAuthentication());
    }

    public static UserModifiedEvent userDeleted(String userId, String username) {
        return new UserModifiedEvent(
            userId,
            username,
            AuditEventType.UserDeletedEvent,
            getContextAuthentication());
    }

    public static UserModifiedEvent userVerified(String userId, String username) {
        return new UserModifiedEvent(
            userId,
            username,
            AuditEventType.UserVerifiedEvent,
            getContextAuthentication());
    }

    @Override
    public AuditEvent getAuditEvent() {
        String[] details = {"user_id="+userId, "username="+username};
        String data = null;
        try {
            data = new ObjectMapper().writeValueAsString(details);
        } catch (IOException e) { }
        return createAuditRecord(
            userId,
            eventType,
            getOrigin(getAuthentication()),
            data);
    }

    public String getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    protected static Authentication getContextAuthentication() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a==null) {
            a = new Authentication() {
                ArrayList<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
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
                }

                @Override
                public String getName() {
                    return "null";
                }
            };
        }
        return a;
    }
}
