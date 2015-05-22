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
package org.cloudfoundry.identity.uaa.authentication.manager;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

/**
 * @author Luke Taylor
 */
public class AuthzAuthenticationManagerTests {
    private AuthzAuthenticationManager mgr;
    private UaaUserDatabase db;
    private ApplicationEventPublisher publisher;
    private static final String PASSWORD = "$2a$10$HoWPAUn9zqmmb0b.2TBZWe6cjQcxyo8TDwTX.5G46PBL347N3/0zO"; // "password"
    private UaaUser user = null;
    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    private String loginServerUserName="loginServerUser".toLowerCase();

    @Before
    public void setUp() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        user = new UaaUser(
            id,
            "auser",
            PASSWORD,
            "auser@blah.com",
            UaaAuthority.USER_AUTHORITIES,
            "A", "User",
            new Date(),
            new Date(),
            Origin.UAA,
            null,
            true,
            IdentityZoneHolder.get().getId(),
            id);
        db = mock(UaaUserDatabase.class);
        publisher = mock(ApplicationEventPublisher.class);
        mgr = new AuthzAuthenticationManager(db, encoder);
        mgr.setApplicationEventPublisher(publisher);
        mgr.setOrigin(Origin.UAA);
    }

    @Test
    public void successfulAuthentication() throws Exception {
        when(db.retrieveUserByName("auser", Origin.UAA)).thenReturn(user);
        Authentication result = mgr.authenticate(createAuthRequest("auser", "password"));
        assertNotNull(result);
        assertEquals("auser", result.getName());
        assertEquals("auser", ((UaaPrincipal) result.getPrincipal()).getName());
    }

    @Test(expected = BadCredentialsException.class)
    public void unsuccessfulLoginServerUserAuthentication() throws Exception {
        when(db.retrieveUserByName(loginServerUserName,Origin.UAA)).thenReturn(null);
        mgr.authenticate(createAuthRequest(loginServerUserName, ""));
    }

    @Test(expected = BadCredentialsException.class)
    public void unsuccessfulLoginServerUserWithPasswordAuthentication() throws Exception {
        when(db.retrieveUserByName(loginServerUserName,Origin.UAA)).thenReturn(null);
        mgr.authenticate(createAuthRequest(loginServerUserName, "dadas"));
    }

    @Test
    public void successfulAuthenticationReturnsTokenAndPublishesEvent() throws Exception {
        when(db.retrieveUserByName("auser",Origin.UAA)).thenReturn(user);
        Authentication result = mgr.authenticate(createAuthRequest("auser", "password"));

        assertNotNull(result);
        assertEquals("auser", result.getName());
        assertEquals("auser", ((UaaPrincipal) result.getPrincipal()).getName());

        verify(publisher).publishEvent(isA(UserAuthenticationSuccessEvent.class));
    }

    @Test
    public void invalidPasswordPublishesAuthenticationFailureEvent() {
        when(db.retrieveUserByName("auser",Origin.UAA)).thenReturn(user);
        try {
            mgr.authenticate(createAuthRequest("auser", "wrongpassword"));
            fail();
        } catch (BadCredentialsException expected) {
        }

        verify(publisher).publishEvent(isA(UserAuthenticationFailureEvent.class));
    }

    @Test(expected = AuthenticationPolicyRejectionException.class)
    public void authenticationIsDeniedIfRejectedByLoginPolicy() throws Exception {
        when(db.retrieveUserByName("auser", Origin.UAA)).thenReturn(user);
        AccountLoginPolicy lp = mock(AccountLoginPolicy.class);
        when(lp.isAllowed(any(UaaUser.class), any(Authentication.class))).thenReturn(false);
        mgr.setAccountLoginPolicy(lp);
        mgr.authenticate(createAuthRequest("auser", "password"));
    }

    @Test
    public void missingUserPublishesNotFoundEvent() {
        when(db.retrieveUserByName(eq("aguess"),eq(Origin.UAA))).thenThrow(new UsernameNotFoundException("mocked"));
        try {
            mgr.authenticate(createAuthRequest("aguess", "password"));
            fail();
        } catch (BadCredentialsException expected) {
        }

        verify(publisher).publishEvent(isA(UserNotFoundEvent.class));
    }

    @Test
    public void successfulVerifyOriginAuthentication1() throws Exception {
        mgr.setOrigin("test");
        user = user.modifySource("test",null);
        when(db.retrieveUserByName("auser","test")).thenReturn(user);
        Authentication result = mgr.authenticate(createAuthRequest("auser", "password"));
        assertNotNull(result);
        assertEquals("auser", result.getName());
        assertEquals("auser", ((UaaPrincipal) result.getPrincipal()).getName());
    }

    @Test(expected = BadCredentialsException.class)
    public void originAuthenticationFail() throws Exception {
        when(db.retrieveUserByName("auser", "not UAA")).thenReturn(user);
        mgr.authenticate(createAuthRequest("auser", "password"));
    }

    @Test
    public void unverifiedAuthenticationSucceedsWhenAllowed() throws Exception {
        user.setVerified(false);
        when(db.retrieveUserByName("auser", Origin.UAA)).thenReturn(user);
        Authentication result = mgr.authenticate(createAuthRequest("auser", "password"));
        assertEquals("auser", result.getName());
        assertEquals("auser", ((UaaPrincipal) result.getPrincipal()).getName());
        }

    @Test
    public void unverifiedAuthenticationFailsWhenNotAllowed() throws Exception {
        mgr.setAllowUnverifiedUsers(false);
        user.setVerified(false);
        when(db.retrieveUserByName("auser", Origin.UAA)).thenReturn(user);
        try {
            mgr.authenticate(createAuthRequest("auser", "password"));

            fail("Expected AccountNotVerifiedException");
        } catch (AccountNotVerifiedException e) {
            // woo hoo
        }
        verify(publisher).publishEvent(isA(UnverifiedUserAuthenticationEvent.class));
    }

    AuthzAuthenticationRequest createAuthRequest(String username, String password) {
        Map<String, String> userdata = new HashMap<String, String>();
        userdata.put("username", username);
        userdata.put("password", password);
        return new AuthzAuthenticationRequest(userdata, new UaaAuthenticationDetails(mock(HttpServletRequest.class)));
    }
}
