/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExtendedLdapUserImpl;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
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
    private static LdapUserDetails userDetails;

    final String DENVER_CO = "Denver,CO";
    final String COST_CENTER = "costCenter";
    final String COST_CENTERS = "costCenters";
    final String JOHN_THE_SLOTH = "John the Sloth";
    final String KARI_THE_ANT_EATER = "Kari the Ant Eater";
    final String UAA_MANAGER = "uaaManager";
    final String MANAGERS = "managers";

    private static LdapUserDetails mockLdapUserDetails() {
        userDetails = mock(LdapUserDetails.class);
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
    IdentityProviderProvisioning provisioning;
    IdentityProvider provider;
    LdapIdentityProviderDefinition definition;

    @Before
    public void setUp() {
        am = new LdapLoginAuthenticationManager();
        publisher = mock(ApplicationEventPublisher.class);
        am.setApplicationEventPublisher(publisher);
        am.setOrigin(origin);
        authUserDetail = getAuthDetails(LDAP_EMAIL, "Marissa", "Bloggs", "8675309");
        auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(authUserDetail);

        UaaUserDatabase db = mock(UaaUserDatabase.class);
        when(db.retrieveUserById(anyString())).thenReturn(dbUser);
        am.setUserDatabase(db);
        when(auth.getAuthorities()).thenReturn(null);

        provider = mock(IdentityProvider.class);
        provisioning = mock(IdentityProviderProvisioning.class);
        when(provisioning.retrieveByOrigin(anyString(),anyString())).thenReturn(provider);
        Map attributeMappings = new HashMap<>();
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "baseUrl",
            "bindUserDn",
            "bindPassword",
            "userSearchBase",
            "userSearchFilter",
            "grouSearchBase",
            "groupSearchFilter",
            "mailAttributeName",
            "mailSubstitute",
            false,
            false,
            false,
            1,
            false
        );
        definition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+MANAGERS, UAA_MANAGER);
        definition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+COST_CENTERS, COST_CENTER);
        when(provider.getConfig()).thenReturn(definition);
        am.setProvisioning(provisioning);
    }

    @Test
    public void testGetUserWithExtendedLdapInfo() throws Exception {
        UaaUser user = am.getUser(auth, null);
        assertEquals(DN, user.getExternalId());
        assertEquals(LDAP_EMAIL, user.getEmail());
        assertEquals(origin, user.getOrigin());
    }

    @Test
    public void testGetUserWithNonLdapInfo() throws Exception {
        UserDetails mockNonLdapUserDetails = mockNonLdapUserDetails();
        when(mockNonLdapUserDetails.getUsername()).thenReturn(TEST_EMAIL);
        when(auth.getPrincipal()).thenReturn(mockNonLdapUserDetails);
        UaaUser user = am.getUser(auth, null);
        assertEquals(TEST_EMAIL, user.getExternalId());
        assertEquals(TEST_EMAIL, user.getEmail());
        assertEquals(origin, user.getOrigin());
    }

    @Test
    public void testUserAuthenticated() throws Exception {


        UaaUser user = getUaaUser();
        UaaUser userFromRequest = am.getUser(auth, null);
        definition.setAutoAddGroups(true);
        UaaUser result = am.userAuthenticated(auth, user, userFromRequest);
        assertSame(dbUser, result);
        verify(publisher, times(1)).publishEvent(Matchers.<ApplicationEvent>anyObject());

        definition.setAutoAddGroups(false);
        result = am.userAuthenticated(auth, userFromRequest, user);
        assertSame(dbUser, result);
        verify(publisher, times(2)).publishEvent(Matchers.<ApplicationEvent>anyObject());
    }

    @Test
    public void shadowUserCreationDisabledWillNotAddShadowUser() throws Exception {
        definition.setAddShadowUserOnLogin(false);
        assertFalse(am.isAddNewShadowUser());
    }

    @Test
    public void update_existingUser_if_attributes_different() throws Exception {
        ExtendedLdapUserImpl authDetails = getAuthDetails(LDAP_EMAIL, "MarissaChanged", "BloggsChanged", "8675309");
        when(auth.getPrincipal()).thenReturn(authDetails);

        UaaUser user = getUaaUser();
        UaaUser userFromRequest = am.getUser(auth, null);
        am.userAuthenticated(auth, userFromRequest, user);
        ArgumentCaptor<ExternalGroupAuthorizationEvent> captor = ArgumentCaptor.forClass(ExternalGroupAuthorizationEvent.class);
        verify(publisher, times(1)).publishEvent(captor.capture());

        assertEquals(LDAP_EMAIL, captor.getValue().getUser().getEmail());
        assertEquals("MarissaChanged", captor.getValue().getUser().getGivenName());
        assertEquals("BloggsChanged", captor.getValue().getUser().getFamilyName());
    }

    @Test
    public void dontUpdate_existingUser_if_attributes_same() throws Exception {
        UaaUser user = getUaaUser();
        ExtendedLdapUserImpl authDetails = getAuthDetails(user.getEmail(), user.getGivenName(), user.getFamilyName(), user.getPhoneNumber());
        when(auth.getPrincipal()).thenReturn(authDetails);

        UaaUser userFromRequest = am.getUser(auth, null);
        am.userAuthenticated(auth, userFromRequest, user);
        ArgumentCaptor<ExternalGroupAuthorizationEvent> captor = ArgumentCaptor.forClass(ExternalGroupAuthorizationEvent.class);
        verify(publisher, times(1)).publishEvent(captor.capture());

        assertEquals(user.getModified(), captor.getValue().getUser().getModified());
    }

    @Test
    public void test_authentication_attributes() throws Exception {

        UaaUser user = getUaaUser();
        ExtendedLdapUserImpl authDetails =
            getAuthDetails(
                user.getEmail(),
                user.getGivenName(),
                user.getFamilyName(),
                user.getPhoneNumber(),
                new AttributeInfo(UAA_MANAGER, new String[] {KARI_THE_ANT_EATER, JOHN_THE_SLOTH}),
                new AttributeInfo(COST_CENTER, new String[] {DENVER_CO})
            );
        when(auth.getPrincipal()).thenReturn(authDetails);

        UaaUserDatabase db = mock(UaaUserDatabase.class);
        when(db.retrieveUserByName(anyString(), eq(OriginKeys.LDAP))).thenReturn(user);
        when(db.retrieveUserById(anyString())).thenReturn(user);
        am.setOrigin(OriginKeys.LDAP);
        am.setUserDatabase(db);

        UaaAuthentication authentication = (UaaAuthentication)am.authenticate(auth);

        assertEquals("Expected two user attributes", 2, authentication.getUserAttributes().size());
        assertNotNull("Expected cost center attribute", authentication.getUserAttributes().get(COST_CENTERS));
        assertEquals(DENVER_CO, authentication.getUserAttributes().getFirst(COST_CENTERS));

        assertNotNull("Expected manager attribute", authentication.getUserAttributes().get(MANAGERS));
        assertEquals("Expected 2 manager attribute values", 2, authentication.getUserAttributes().get(MANAGERS).size());
        assertThat(authentication.getUserAttributes().get(MANAGERS), containsInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));

        assertThat(authentication.getAuthenticationMethods(), containsInAnyOrder("ext", "pwd"));


    }

    private ExtendedLdapUserImpl getAuthDetails(String email, String givenName, String familyName, String phoneNumber, AttributeInfo... attributes) {
        String[] emails = {email};
        String[] given_names = {givenName};
        String[] family_names = {familyName};
        String[] phone_numbers = {phoneNumber};
        info.put(EMAIL_ATTRIBUTE, emails);
        info.put(GIVEN_NAME_ATTRIBUTE, given_names);
        info.put(FAMILY_NAME_ATTRIBUTE, family_names);
        info.put(PHONE_NUMBER_ATTTRIBUTE, phone_numbers);
        for (AttributeInfo i : attributes) {
            info.put(i.getName(), i.getValues());
        }

        authUserDetail = new ExtendedLdapUserImpl(mockLdapUserDetails(), info);
        authUserDetail.setMailAttributeName(EMAIL_ATTRIBUTE);
        authUserDetail.setGivenNameAttributeName(GIVEN_NAME_ATTRIBUTE);
        authUserDetail.setFamilyNameAttributeName(FAMILY_NAME_ATTRIBUTE);
        authUserDetail.setPhoneNumberAttributeName(PHONE_NUMBER_ATTTRIBUTE);
        return authUserDetail;
    }

    protected UaaUser getUaaUser() {
        return new UaaUser(new UaaUserPrototype()
                               .withId("id")
                               .withUsername(USERNAME)
                               .withPassword("password")
                               .withEmail(TEST_EMAIL)
                               .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                               .withGivenName("givenname")
                               .withFamilyName("familyname")
                               .withPhoneNumber("8675309")
                               .withCreated(new Date())
                               .withModified(new Date())
                               .withOrigin(OriginKeys.ORIGIN)
                               .withExternalId(DN)
                               .withVerified(false)
                               .withZoneId(IdentityZoneHolder.get().getId())
                               .withSalt(null)
                               .withPasswordLastModified(null));
    }


    public static class AttributeInfo {
        final String name;
        final String[] values;

        public AttributeInfo(String name, String[] values) {
            this.name = name;
            this.values = values;
        }

        public String getName() {
            return name;
        }

        public String[] getValues() {
            return values;
        }
    }
}
