package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExtendedLdapUserImpl;
import org.cloudfoundry.identity.uaa.user.Mailable;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.*;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

public class ExternalLoginAuthenticationManagerTest  {

    private ApplicationEventPublisher applicationEventPublisher;
    private UaaUserDatabase uaaUserDatabase;
    private Authentication inputAuth;
    private ExternalLoginAuthenticationManager manager;
    private String origin = "test";
    private String beanName = "ExternalLoginAuthenticationManagerTestBean";
    private UserDetails userDetails;
    private String userName="testUserName";
    private String password = "";
    private UaaUser user;
    private String userId = new RandomValueStringGenerator().generate();
    private ArgumentCaptor<ApplicationEvent> userArgumentCaptor;
    private IdentityProviderProvisioning providerProvisioning;
    private MultiValueMap<String, String> userAttributes;
    private List<String> externalGroups;

    private void mockUserDetails(UserDetails userDetails) {
        when(userDetails.getUsername()).thenReturn(userName);
        when(userDetails.getPassword()).thenReturn(password);
        when(userDetails.getAuthorities()).thenReturn(null);
        when(userDetails.isAccountNonExpired()).thenReturn(true);
        when(userDetails.isAccountNonLocked()).thenReturn(true);
        when(userDetails.isCredentialsNonExpired()).thenReturn(true);
        when(userDetails.isEnabled()).thenReturn(true);
    }

    @Before
    public void setUp() {
        userDetails = mock(UserDetails.class);
        mockUserDetails(userDetails);
        mockUaaWithUser();
        userAttributes = new LinkedMultiValueMap<>();
        userAttributes.put("1", Collections.singletonList("1"));
        userAttributes.put("2", Arrays.asList("2", "3"));
        externalGroups = Arrays.asList("role1", "role2", "role3");
    }

    private void mockUaaWithUser() {
        applicationEventPublisher = mock(ApplicationEventPublisher.class);

        uaaUserDatabase = mock(UaaUserDatabase.class);

        user = addUserToDb(userName, userId, origin, "test@email.org");

        inputAuth = mock(Authentication.class);
        when(inputAuth.getPrincipal()).thenReturn(userDetails);

        manager = new ExternalLoginAuthenticationManager(null);
        setupManager();
    }

    private UaaUser addUserToDb(String userName, String userId, String origin, String email) {
        UaaUser user = mock(UaaUser.class);
        when(user.getUsername()).thenReturn(userName);
        when(user.getId()).thenReturn(userId);
        when(user.getOrigin()).thenReturn(origin);
        when(user.getEmail()).thenReturn(email);

        when(this.uaaUserDatabase.retrieveUserById(eq(userId))).thenReturn(user);
        when(this.uaaUserDatabase.retrieveUserByName(eq(userName),eq(origin))).thenReturn(user);
        return user;
    }

    private void setupManager() {
        manager.setOrigin(origin);
        manager.setBeanName(beanName);
        manager.setApplicationEventPublisher(applicationEventPublisher);
        manager.setUserDatabase(uaaUserDatabase);
        providerProvisioning = mock(IdentityProviderProvisioning.class);
        manager.setProviderProvisioning(providerProvisioning);
    }

    @Test
    public void testAuthenticateNullPrincipal() {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(null);
        Authentication result = manager.authenticate(auth);
        assertNull(result);
    }

    @Test
    public void testAuthenticateUnknownPrincipal() {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(userName);
        Authentication result = manager.authenticate(auth);
        assertNull(result);
    }

    @Test
    public void testAuthenticateUsernamePasswordToken() {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userName,password);
        Authentication result = manager.authenticate(auth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(userName,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin,uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testAuthenticateUserDetailsPrincipal() {
        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(userName,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin,uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testAuthenticateWithAuthDetails() {
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(uaaAuthenticationDetails.getOrigin()).thenReturn(origin);
        when(uaaAuthenticationDetails.getClientId()).thenReturn(null);
        when(uaaAuthenticationDetails.getSessionId()).thenReturn(new RandomValueStringGenerator().generate());
        when(inputAuth.getDetails()).thenReturn(uaaAuthenticationDetails);

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(userName,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin,uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testNoUsernameOnlyEmail() {
        String email = "joe@test.org";

        userDetails = mock(UserDetails.class, withSettings().extraInterfaces(Mailable.class));
        when(((Mailable)userDetails).getEmailAddress()).thenReturn(email);
        mockUserDetails(userDetails);
        mockUaaWithUser();

        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(uaaAuthenticationDetails.getOrigin()).thenReturn(origin);
        when(uaaAuthenticationDetails.getClientId()).thenReturn(null);
        when(uaaAuthenticationDetails.getSessionId()).thenReturn(new RandomValueStringGenerator().generate());
        when(inputAuth.getDetails()).thenReturn(uaaAuthenticationDetails);
        when(user.getUsername()).thenReturn(email);
        when(uaaUserDatabase.retrieveUserByName(email, origin))
            .thenReturn(user);

        when(userDetails.getUsername()).thenReturn(null);
        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;

        assertEquals(email,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin, uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());
    }

    @Test(expected = BadCredentialsException.class)
    public void testNoUsernameNoEmail() {
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(uaaAuthenticationDetails.getOrigin()).thenReturn(origin);
        when(uaaAuthenticationDetails.getClientId()).thenReturn(null);
        when(uaaAuthenticationDetails.getSessionId()).thenReturn(new RandomValueStringGenerator().generate());
        when(inputAuth.getDetails()).thenReturn(uaaAuthenticationDetails);
        when(uaaUserDatabase.retrieveUserByName(anyString(), eq(origin))).thenReturn(null);
        when(userDetails.getUsername()).thenReturn(null);
        manager.authenticate(inputAuth);
    }

    @Test
    public void testAmpersandInName() {
        String name = "filip@hanik";
        when(userDetails.getUsername()).thenReturn(name);
        when(user.getUsername()).thenReturn(name);
        when(uaaUserDatabase.retrieveUserByName(eq(name),eq(origin)))
            .thenReturn(null)
            .thenReturn(user);

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(name,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin, uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testAmpersandInEndOfName() {
        String name = "filip@hanik@";
        String actual = name.replaceAll("@","") +  "@user.from."+origin+".cf";
        when(userDetails.getUsername()).thenReturn(name);
        when(user.getUsername()).thenReturn(name);
        when(uaaUserDatabase.retrieveUserByName(eq(name),eq(origin)))
            .thenReturn(null)
            .thenReturn(user);

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(name,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin, uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());

        userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(applicationEventPublisher,times(2)).publishEvent(userArgumentCaptor.capture());
        assertEquals(2,userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent)userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, event.getUser().getOrigin());
        assertEquals(actual, event.getUser().getEmail());

    }

    @Test(expected = BadCredentialsException.class)
    public void testAuthenticateUserInsertFails() {
        when(uaaUserDatabase.retrieveUserByName(anyString(),anyString())).thenThrow(new UsernameNotFoundException(""));
        manager.authenticate(inputAuth);
    }

    @Test
    public void testAuthenticateLdapUserDetailsPrincipal() {
        String dn = "cn="+userName+",ou=Users,dc=test,dc=com";
        String origin = LDAP;
        LdapUserDetails ldapUserDetails = mock(LdapUserDetails.class);
        mockUserDetails(ldapUserDetails);
        when(ldapUserDetails.getDn()).thenReturn(dn);
        manager = new LdapLoginAuthenticationManager(null);
        setupManager();
        manager.setProviderProvisioning(null);
        manager.setOrigin(origin);
        when(user.getOrigin()).thenReturn(origin);
        when(uaaUserDatabase.retrieveUserByName(eq(userName), eq(origin))).thenReturn(user);
        when(inputAuth.getPrincipal()).thenReturn(ldapUserDetails);

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(userName,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin,uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testShadowUserCreationDisabled() {
        String dn = "cn="+userName+",ou=Users,dc=test,dc=com";
        String origin = LDAP;
        LdapUserDetails ldapUserDetails = mock(LdapUserDetails.class);
        mockUserDetails(ldapUserDetails);
        when(ldapUserDetails.getDn()).thenReturn(dn);
        manager = new LdapLoginAuthenticationManager(null) {
            @Override
            protected boolean isAddNewShadowUser() {
                return false;
            }
        };

        setupManager();
        manager.setOrigin(origin);
        when(uaaUserDatabase.retrieveUserByName(eq(userName), eq(origin))).thenReturn(null);
        when(inputAuth.getPrincipal()).thenReturn(ldapUserDetails);

        try {
            manager.authenticate(inputAuth);
            fail("Expected authentication to fail with an exception.");
        } catch (AccountNotPreCreatedException ex) {
            assertThat(ex.getMessage(), containsString("user account must be pre-created"));
        }

        verify(applicationEventPublisher, times(0)).publishEvent(any());
    }

    @Test
    public void testAuthenticateCreateUserWithLdapUserDetailsPrincipal() {
        String dn = "cn="+userName+",ou=Users,dc=test,dc=com";
        String origin = LDAP;
        String email = "joe@test.org";

        LdapUserDetails baseLdapUserDetails = mock(LdapUserDetails.class);
        mockUserDetails(baseLdapUserDetails);
        when(baseLdapUserDetails.getDn()).thenReturn(dn);
        HashMap<String, String[]> ldapAttrs = new HashMap<>();
        String ldapMailAttrName = "email";
        ldapAttrs.put(ldapMailAttrName, new String[]{email});
        ExtendedLdapUserImpl ldapUserDetails = new ExtendedLdapUserImpl(baseLdapUserDetails, ldapAttrs);
        ldapUserDetails.setMailAttributeName(ldapMailAttrName);

        manager = new LdapLoginAuthenticationManager(null);
        setupManager();
        manager.setProviderProvisioning(null);
        manager.setOrigin(origin);
        when(user.getEmail()).thenReturn(email);
        when(user.getOrigin()).thenReturn(origin);
        when(uaaUserDatabase.retrieveUserByName(eq(userName),eq(origin)))
            .thenReturn(null)
            .thenReturn(user);
        when(inputAuth.getPrincipal()).thenReturn(ldapUserDetails);

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(userName,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin,uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());

        userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(applicationEventPublisher,times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3,userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent)userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, event.getUser().getOrigin());
        assertEquals(dn, event.getUser().getExternalId());
    }

    @Test
    public void testAuthenticateCreateUserWithUserDetailsPrincipal() {
        String origin = LDAP;

        manager = new LdapLoginAuthenticationManager(null);
        setupManager();
        manager.setOrigin(origin);
        manager.setProviderProvisioning(null);

        when(user.getOrigin()).thenReturn(origin);
        when(uaaUserDatabase.retrieveUserByName(eq(userName),eq(origin)))
            .thenReturn(null)
            .thenReturn(user);

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(userName,uaaAuthentication.getPrincipal().getName());
        assertEquals(origin,uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());

        userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(applicationEventPublisher,times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3,userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent)userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, event.getUser().getOrigin());
        //incorrect user details - we wont be able to get the correct external ID
        assertEquals(userName, event.getUser().getExternalId());
    }

    @Test
    public void testAuthenticateInvitedUserWithoutAcceptance() {
        String username = "guyWhoDoesNotAcceptInvites";
        String origin = LDAP;
        String email = "guy@ldap.org";

        UserDetails ldapUserDetails = mock(ExtendedLdapUserDetails.class, withSettings().extraInterfaces(Mailable.class));
        when(ldapUserDetails.getUsername()).thenReturn(username);
        when(ldapUserDetails.getPassword()).thenReturn(password);
        when(ldapUserDetails.getAuthorities()).thenReturn(null);
        when(ldapUserDetails.isAccountNonExpired()).thenReturn(true);
        when(ldapUserDetails.isAccountNonLocked()).thenReturn(true);
        when(ldapUserDetails.isCredentialsNonExpired()).thenReturn(true);
        when(ldapUserDetails.isEnabled()).thenReturn(true);
        when(((Mailable) ldapUserDetails).getEmailAddress()).thenReturn(email);

        // Invited users are created with their email as their username.
        UaaUser invitedUser = addUserToDb(email, userId, origin, email);
        when(invitedUser.modifyAttributes(anyString(), anyString(), anyString(), anyString(), anyBoolean())).thenReturn(invitedUser);
        UaaUser updatedUser = new UaaUser(new UaaUserPrototype().withUsername(username).withId(userId).withOrigin(origin).withEmail(email));
        when(invitedUser.modifyUsername(username)).thenReturn(updatedUser);

        manager = new LdapLoginAuthenticationManager(null);
        setupManager();
        manager.setProviderProvisioning(null);
        manager.setOrigin(origin);

        when(uaaUserDatabase.retrieveUserByName(eq(username),eq(origin)))
                .thenThrow(new UsernameNotFoundException(""));
        when(uaaUserDatabase.retrieveUserByEmail(eq(email), eq(origin)))
                .thenReturn(invitedUser);

        Authentication ldapAuth = mock(Authentication.class);
        when(ldapAuth.getPrincipal()).thenReturn(ldapUserDetails);

        manager.authenticate(ldapAuth);

        userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(applicationEventPublisher, atLeastOnce()).publishEvent(userArgumentCaptor.capture());

        for(ApplicationEvent event : userArgumentCaptor.getAllValues()) {
            assertNotEquals(event.getClass(), NewUserAuthenticatedEvent.class);
        }
    }

    @Test
    public void testPopulateAttributesStoresCustomAttributesAndRoles() {
        manager = new LdapLoginAuthenticationManager(null);
        setupManager();
        manager.setOrigin(origin);
        IdentityProvider provider = mock(IdentityProvider.class);
        ExternalIdentityProviderDefinition providerDefinition = new ExternalIdentityProviderDefinition();
        when(provider.getConfig()).thenReturn(providerDefinition);
        when(providerProvisioning.retrieveByOrigin(eq(origin), anyString())).thenReturn(provider);
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        UaaPrincipal uaaPrincipal = mock(UaaPrincipal.class);
        when(uaaPrincipal.getId()).thenReturn("id");
        when(uaaAuthentication.getPrincipal()).thenReturn(uaaPrincipal);
        when(uaaAuthentication.getUserAttributes()).thenReturn(userAttributes);
        HashSet<String> externalGroupsOnAuthentication = new HashSet<>(externalGroups);
        when(uaaAuthentication.getExternalGroups()).thenReturn(externalGroupsOnAuthentication);

        providerDefinition.setStoreCustomAttributes(false);
        manager.populateAuthenticationAttributes(uaaAuthentication, mock(Authentication.class), null);
        verify(manager.getUserDatabase(), never()).storeUserInfo(anyString(), any());

        // when there are both attributes and groups, store them
        providerDefinition.setStoreCustomAttributes(true);
        manager.populateAuthenticationAttributes(uaaAuthentication, mock(Authentication.class), null);
        UserInfo userInfo = new UserInfo()
            .setUserAttributes(userAttributes)
            .setRoles(externalGroups);
        verify(manager.getUserDatabase(), times(1)).storeUserInfo(eq("id"), eq(userInfo));

        // when provider is null do not store anything
        reset(manager.getUserDatabase());
        manager.setProviderProvisioning(null);
        manager.populateAuthenticationAttributes(uaaAuthentication, mock(Authentication.class), null);
        verify(manager.getUserDatabase(), never()).storeUserInfo(anyString(), any());

        manager.setProviderProvisioning(providerProvisioning);

        // when attributes is empty but roles have contents, store it
        reset(manager.getUserDatabase());
        userAttributes.clear();
        manager.populateAuthenticationAttributes(uaaAuthentication, mock(Authentication.class), null);
        userInfo = new UserInfo()
                .setUserAttributes(userAttributes)
                .setRoles(externalGroups);
        verify(manager.getUserDatabase(), times(1)).storeUserInfo(eq("id"), eq(userInfo));

        // when attributes and roles are both empty, do not store anything
        reset(manager.getUserDatabase());
        userAttributes.clear();
        externalGroupsOnAuthentication.clear();
        manager.populateAuthenticationAttributes(uaaAuthentication, mock(Authentication.class), null);
        verify(manager.getUserDatabase(), never()).storeUserInfo(anyString(), any());
    }

    @Test
    public void testAuthenticateUserExists() {
        Authentication result = manager.authenticate(inputAuth);
        userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(applicationEventPublisher,times(1)).publishEvent(userArgumentCaptor.capture());
        assertEquals(1,userArgumentCaptor.getAllValues().size());
        IdentityProviderAuthenticationSuccessEvent userevent = (IdentityProviderAuthenticationSuccessEvent)userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, userevent.getUser().getOrigin());
        assertEquals(userName, userevent.getUser().getUsername());
    }

    @Test
    public void testAuthenticateUserDoesNotExists() {
        String origin = "external";
        manager.setOrigin(origin);

        when(uaaUserDatabase.retrieveUserByName(eq(userName), eq(origin)))
            .thenReturn(null)
            .thenReturn(user);

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication)result;
        assertEquals(userName,uaaAuthentication.getPrincipal().getName());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());

        userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(applicationEventPublisher,times(2)).publishEvent(userArgumentCaptor.capture());
        assertEquals(2,userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent)userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, event.getUser().getOrigin());
    }



}