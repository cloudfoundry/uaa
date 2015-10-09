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
import org.springframework.security.core.userdetails.UserDetails;
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

public class LdapLoginAuthenticationManagerTests {

    public static final String DN = "cn=marissa,ou=Users,dc=test,dc=com";
    public static final String LDAP_EMAIL = "test@ldap.org";
    public static final String TEST_EMAIL = "email@email.org";
    public static final String USERNAME = "username";
    private static final String EMAIL_ATTRIBUTE = "email";
    private final String GIVEN_NAME_ATTRIBUTE = "firstname";
    private final String FAMILY_NAME_ATTRIBUTE = "surname";
    private final String PHONE_NUMBER_ATTTRIBUTE = "digits";

    private static LdapUserDetails mockLdapUserDetails() {
        LdapUserDetails userDetails = mock(LdapUserDetails.class);
        setupGeneralExpectations(userDetails);
        when(userDetails.getDn()).thenReturn(DN);
        return userDetails;
    }

    private static UserDetails mockNonLdapUserDetails() {
        UserDetails userDetails = mock(UserDetails.class);
        setupGeneralExpectations(userDetails);
        return userDetails;
    }

    private static void setupGeneralExpectations(UserDetails userDetails) {
        when(userDetails.getUsername()).thenReturn(USERNAME);
        when(userDetails.getPassword()).thenReturn("koala");
        when(userDetails.getAuthorities()).thenReturn(null);
        when(userDetails.isAccountNonExpired()).thenReturn(true);
        when(userDetails.isAccountNonLocked()).thenReturn(true);
        when(userDetails.isCredentialsNonExpired()).thenReturn(true);
        when(userDetails.isEnabled()).thenReturn(true);
    }

    LdapLoginAuthenticationManager am;
    ApplicationEventPublisher publisher;
    String origin = "test";
    Map<String, String[]> info = new HashMap<>();
    UaaUser dbUser = getUaaUser();
    Authentication auth;
    ExtendedLdapUserImpl authUserDetail;


    @Before
    public void setUp() {
        am = new LdapLoginAuthenticationManager();
        publisher = mock(ApplicationEventPublisher.class);
        am.setApplicationEventPublisher(publisher);
        am.setOrigin(origin);
        info = new HashMap<>();
        String[] emails = {LDAP_EMAIL};
        String[] given_names = {"Marissa"};
        String[] family_names = {"Bloggs"};
        String[] phone_numbers = {"8675309"};
        info.put(EMAIL_ATTRIBUTE, emails);
        info.put(GIVEN_NAME_ATTRIBUTE, given_names);
        info.put(FAMILY_NAME_ATTRIBUTE, family_names);
        info.put(PHONE_NUMBER_ATTTRIBUTE, phone_numbers);
        UaaUserDatabase db = mock(UaaUserDatabase.class);
        when(db.retrieveUserById(anyString())).thenReturn(dbUser);
        am.setUserDatabase(db);
        auth = mock(Authentication.class);
        when(auth.getAuthorities()).thenReturn(null);
        authUserDetail = new ExtendedLdapUserImpl(mockLdapUserDetails(), info);
        authUserDetail.setMailAttributeName(EMAIL_ATTRIBUTE);
        authUserDetail.setGivenNameAttributeName(GIVEN_NAME_ATTRIBUTE);
        authUserDetail.setFamilyNameAttributeName(FAMILY_NAME_ATTRIBUTE);
        authUserDetail.setPhoneNumberAttributeName(PHONE_NUMBER_ATTTRIBUTE);
        when(auth.getPrincipal()).thenReturn(authUserDetail);
    }

    @Test
    public void testGetUserWithExtendedLdapInfo() throws Exception {
        UaaUser user = am.getUser(auth);
        assertEquals(DN, user.getExternalId());
        assertEquals(LDAP_EMAIL, user.getEmail());
        assertEquals(origin, user.getOrigin());
    }

    @Test
    public void testGetUserWithNonLdapInfo() throws Exception {
        UserDetails mockNonLdapUserDetails = mockNonLdapUserDetails();
        when(mockNonLdapUserDetails.getUsername()).thenReturn(TEST_EMAIL);
        when(auth.getPrincipal()).thenReturn(mockNonLdapUserDetails);
        UaaUser user = am.getUser(auth);
        assertEquals(TEST_EMAIL, user.getExternalId());
        assertEquals(TEST_EMAIL, user.getEmail());
        assertEquals(origin, user.getOrigin());
    }

    @Test
    public void testUserAuthenticated() throws Exception {
        UaaUser user = getUaaUser();
        am.setAutoAddAuthorities(true);
        UaaUser result = am.userAuthenticated(auth, user);
        assertSame(dbUser, result);
        verify(publisher, times(1)).publishEvent(Matchers.<ApplicationEvent>anyObject());

        am.setAutoAddAuthorities(false);
        result = am.userAuthenticated(auth, user);
        assertSame(dbUser, result);
        verify(publisher, times(2)).publishEvent(Matchers.<ApplicationEvent>anyObject());
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
                DN,
                false,
                IdentityZoneHolder.get().getId(),
                null,
                null);
    }
}