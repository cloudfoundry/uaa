/*
 * ******************************************************************************
 *  *     Cloud Foundry
 *  *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *  *
 *  *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  *     You may not use this product except in compliance with the License.
 *  *
 *  *     This product includes a number of subcomponents with
 *  *     separate copyright notices and license terms. Your use of these
 *  *     subcomponents is subject to the terms and conditions of the
 *  *     subcomponent's license, as noted in the LICENSE file.
 *  ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.util.ReflectionUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SessionResetFilterTests {

    SessionResetFilter filter;
    HttpServletResponse response;
    HttpServletRequest request;
    HttpSession session;
    FilterChain chain;
    UaaUserDatabase userDatabase;
    UaaAuthentication authentication;
    Date yesterday;
    UaaUser user;
    UaaUser userWithNoPasswordModification;

    @BeforeEach
    void setUpFilter() {

        yesterday = new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24));

        addUsersToInMemoryDb();

        UaaPrincipal principal = new UaaPrincipal(user);

        authentication = new UaaAuthentication(principal, null, Collections.emptyList(), null, true, System.currentTimeMillis());

        chain = mock(FilterChain.class);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        session = mock(HttpSession.class);
        when(request.getSession(anyBoolean())).thenReturn(session);
        filter = new SessionResetFilter(new DefaultRedirectStrategy(), new IdentityZoneManagerImpl(),"/login", userDatabase);
    }

    private void addUsersToInMemoryDb() {
        user = new UaaUser(
                "user-id",
                "username",
                "password",
                "email",
                Collections.emptyList(),
                "given name",
                "family name",
                yesterday,
                yesterday,
                OriginKeys.UAA,
                null,
                true,
                IdentityZone.getUaaZoneId(),
                "salt",
                yesterday
        );

        userWithNoPasswordModification = new UaaUser(
                "user-id-1",
                "username-1",
                "password",
                "email",
                Collections.emptyList(),
                "given name",
                "family name",
                yesterday,
                yesterday,
                OriginKeys.UAA,
                null,
                true,
                IdentityZone.getUaaZoneId(),
                "salt",
                null
        );

        List<UaaUser> users = new ArrayList<>();
        users.add(user);
        users.add(userWithNoPasswordModification);
        userDatabase = new InMemoryUaaUserDatabase(users);
    }

    @AfterEach
    void clearThingsUp() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    void noAuthenticationPresent() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(request, response);
    }

    @Test
    void noUAAAuthenticationPresent() throws Exception {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("test", "test");
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(request, response);
        verifyNoInteractions(request);
        verifyNoInteractions(response);
    }

    @Test
    void passwordNotModifiedDoesNotCheckAuthTime() throws Exception {
        UaaPrincipal principal = new UaaPrincipal(userWithNoPasswordModification);
        Authentication authentication = new UaaAuthentication(principal, null, Collections.emptyList(), null, true, System.currentTimeMillis());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(request, response);
    }

    @Test
    void userModifiedAfterAuthentication() throws Exception {
        setFieldValue("authenticatedTime", (yesterday.getTime() - (1000 * 60 * 60 * 24)), authentication);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filter.doFilterInternal(request, response, chain);

        //user is not forwarded, and error response is generated right away
        Mockito.verifyNoInteractions(chain);
        //user redirect
        verify(response, times(1)).sendRedirect(any());
        //session was requested
        verify(request, times(2)).getSession(false);
        //session was invalidated
        verify(session, times(1)).invalidate();
    }

    @Test
    void userNotModified() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(request, response);
        verifyNoInteractions(response);
    }

    @Test
    void userNotOriginatedInUaa() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        setFieldValue("origin", OriginKeys.LDAP, authentication.getPrincipal());
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(request, response);
        verifyNoInteractions(request);
        verifyNoInteractions(response);
    }

    @Test
    void userNotFound() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        setFieldValue("id", "invalid-user-id", authentication.getPrincipal());
        filter.doFilterInternal(request, response, chain);

        //user is not forwarded, and error response is generated right away
        Mockito.verifyNoInteractions(chain);
        //user redirect
        verify(response, times(1)).sendRedirect(any());
        //session was requested
        verify(request, times(2)).getSession(false);
        //session was invalidated
        verify(session, times(1)).invalidate();
    }

    protected long dropMilliSeconds(long time) {
        return (time / 1000l) * 1000l;
    }

    protected void setFieldValue(String fieldname, Object value, Object object) {
        Field f = ReflectionUtils.findField(object.getClass(), fieldname);
        ReflectionUtils.makeAccessible(f);
        ReflectionUtils.setField(f, object, value);
    }

}
