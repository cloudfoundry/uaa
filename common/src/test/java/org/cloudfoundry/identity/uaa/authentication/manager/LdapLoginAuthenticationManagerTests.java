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
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.ldap.extension.ExtendedLdapUserImpl;
import org.cloudfoundry.identity.uaa.ldap.extension.SpringSecurityLdapTemplate;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class LdapLoginAuthenticationManagerTests  {

    public static final String DN = "cn=marissa,ou=Users,dc=test,dc=com";
    public static final String LDAP_EMAIL = "test@ldap.org";
    public static final String TEST_EMAIL = "email@email.org";
    public static final String EXTERNAL_ID = "externalId";
    public static final String USERNAME = "username";
    LdapLoginAuthenticationManager am;
    ApplicationEventPublisher publisher;
    String origin = "test";
    Map<String,String> info;
    UaaUser dbUser = getUaaUser();
    Authentication auth;

    @Before
    public void setUp() {
        am = new LdapLoginAuthenticationManager();
        publisher = mock(ApplicationEventPublisher.class);
        am.setApplicationEventPublisher(publisher);
        am.setOrigin(origin);
        info = new HashMap<>();
        info.put("email",TEST_EMAIL);
        UaaUserDatabase db = mock(UaaUserDatabase.class);
        when(db.retrieveUserById(anyString())).thenReturn(dbUser);
        am.setUserDatabase(db);
        auth = mock(Authentication.class);
        when(auth.getAuthorities()).thenReturn(null);
    }

    @Test
    public void testGetUserWithExtendedLdapInfo() throws Exception {
        UaaUser user = am.getUser(getExtendedLdapUserDetails(), info);
        assertEquals(DN, user.getExternalId());
        assertEquals(LDAP_EMAIL, user.getEmail());
        assertEquals(origin, user.getOrigin());
    }

    @Test
    public void testGetUserWithLdapInfo() throws Exception {
        UaaUser user = am.getUser(getLdapUserDetails(), info);
        assertEquals(DN, user.getExternalId());
        assertEquals(TEST_EMAIL, user.getEmail());
        assertEquals(origin, user.getOrigin());
    }

    @Test
    public void testGetUserWithNonLdapInfo() throws Exception {
        UaaUser user = am.getUser(getUserDetails(), info);
        assertEquals(USERNAME, user.getExternalId());
        assertEquals(TEST_EMAIL, user.getEmail());
        assertEquals(origin, user.getOrigin());
    }

    @Test
    public void testUserAuthenticated() throws Exception {
        UaaUser user = getUaaUser();
        am.setAutoAddAuthorities(true);
        UaaUser result = am.userAuthenticated(auth, user);
        assertSame(dbUser,result);
        verify(publisher,times(1)).publishEvent(Matchers.<ApplicationEvent>anyObject());

        am.setAutoAddAuthorities(false);
        result = am.userAuthenticated(auth, user);
        assertSame(dbUser,result);
        verify(publisher,times(2)).publishEvent(Matchers.<ApplicationEvent>anyObject());
    }

    protected User getUserDetails() {
        UaaUser uaaUser = getUaaUser();
        return new User(
            uaaUser.getUsername(),
            uaaUser.getPassword(),
            true,
            true,
            true,
            true,
            uaaUser.getAuthorities()
        );
    }

    protected LdapUserDetails getLdapUserDetails() {
        UaaUser uaaUser = getUaaUser();
        LdapUserDetailsImpl.Essence essence = new LdapUserDetailsImpl.Essence();
        essence.setDn(DN);
        essence.setUsername(uaaUser.getUsername());
        essence.setPassword(uaaUser.getPassword());
        essence.setEnabled(true);
        essence.setAccountNonExpired(true);
        essence.setCredentialsNonExpired(true);
        essence.setAccountNonLocked(true);
        essence.setAuthorities(uaaUser.getAuthorities());
        return essence.createUserDetails();
    }

    protected ExtendedLdapUserDetails getExtendedLdapUserDetails() {
        Map<String,String[]> attributes = new HashMap<>();
        LdapUserDetails details = getLdapUserDetails();
        attributes.put(SpringSecurityLdapTemplate.DN_KEY, new String[] {details.getDn()});
        attributes.put("mail", new String[] {LDAP_EMAIL});
        ExtendedLdapUserImpl result = new ExtendedLdapUserImpl(details,attributes);
        return result;
    }

    protected UaaUser getUaaUser() {
        return new UaaUser(
            "id",
            USERNAME,
            "password",
            TEST_EMAIL,
            UaaAuthority.USER_AUTHORITIES,
            "givenname",
            "familyname",
            new Date(),
            new Date(),
            Origin.ORIGIN,
            EXTERNAL_ID,
            false,
            IdentityZoneHolder.get().getId(),
            null);
    }
}