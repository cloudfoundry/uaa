package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.EmailDomainNotAllowedException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.LinkedMultiValueMap;

import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.AuthenticationBuilder.aUaaAuthentication;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.AuthenticationBuilder.anAuthentication;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.ExtendedLdapUserImplBuilder.anExtendedLdapUserImpl;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.ExternalLoginAuthenticationManagerBuilder.aManager;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.LdapLoginAuthenticationManagerBuilder.anLdapManager;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.UaaAuthenticationDetailsBuilder.aUaaAuthenticationDetails;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.UaaPrincipalBuilder.aUaaPrincipal;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.UaaUserBuilder.aUaaUser;
import static org.cloudfoundry.identity.uaa.authentication.manager.builders.UserDetailsBuilder.*;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

public class ExternalLoginAuthenticationManagerTest {
    @Test
    public void testAuthenticateNullPrincipal() {
        Authentication inputAuth = anAuthentication().withPrincipal((String) null).build();

        Authentication result = aManager().build().authenticate(inputAuth);

        assertNull(result);
    }

    @Test
    public void testAuthenticateUnknownPrincipal() {
        Authentication inputAuth = anAuthentication().withPrincipal("username").build();

        Authentication result = aManager().build().authenticate(inputAuth);

        assertNull(result);
    }

    @Test
    public void testAuthenticateUsernamePasswordToken() {
        ExternalLoginAuthenticationManager manager = aManager()
                .withOrigin("origin")
                .withUaaUser(aUaaUser().withId("userId").withUsername("my_username").withOrigin("origin"))
                .build();
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("my_username", "password");

        Authentication result = manager.authenticate(auth);

        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals("my_username", uaaAuthentication.getPrincipal().getName());
        assertEquals("origin", uaaAuthentication.getPrincipal().getOrigin());
        assertEquals("userId", uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testAuthenticateUserDetailsPrincipal() {
        ExternalLoginAuthenticationManager manager = aManager()
                .withOrigin("origin")
                .withUaaUser(aUaaUser().withId("userId").withUsername("my_username").withOrigin("origin"))
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aUserDetails().withUsername("my_username").withPassword("password"))
                .build();

        Authentication result = manager.authenticate(inputAuth);

        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals("my_username", uaaAuthentication.getPrincipal().getName());
        assertEquals("origin", uaaAuthentication.getPrincipal().getOrigin());
        assertEquals("userId", uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testAuthenticateWithAuthDetails() {
        ExternalLoginAuthenticationManager manager = aManager()
                .withOrigin("origin")
                .withUaaUser(aUaaUser().withId("userId").withUsername("my_username").withOrigin("origin"))
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aUserDetails().withUsername("my_username").withPassword("password"))
                .withDetails(aUaaAuthenticationDetails().withOrigin("origin")).build();

        Authentication result = manager.authenticate(inputAuth);

        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals("my_username", uaaAuthentication.getPrincipal().getName());
        assertEquals("origin", uaaAuthentication.getPrincipal().getOrigin());
        assertEquals("userId", uaaAuthentication.getPrincipal().getId());
        UaaAuthenticationDetails details = (UaaAuthenticationDetails) uaaAuthentication.getDetails();
        assertEquals("origin", details.getOrigin());
    }

    @Test
    public void testNoUsernameOnlyEmail() {
        String email = "joe@test.org";

        ExternalLoginAuthenticationManager manager = aManager()
                .withOrigin("origin")
                .withUaaUser(aUaaUser().withUsername(email).withOrigin("origin").withId("userId"))
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aMailableUserDetails().withUsername(null).withEmailAddress(email))
                .build();

        Authentication authResult = manager.authenticate(inputAuth);

        assertNotNull(authResult);
        assertEquals(UaaAuthentication.class, authResult.getClass());
        UaaAuthentication uaaAuthResult = (UaaAuthentication) authResult;

        assertEquals(email, uaaAuthResult.getPrincipal().getName());
        assertEquals("origin", uaaAuthResult.getPrincipal().getOrigin());
        assertEquals("userId", uaaAuthResult.getPrincipal().getId());
    }

    @Test(expected = BadCredentialsException.class)
    public void testNoUsernameNoEmail() {
        ExternalLoginAuthenticationManager manager = aManager().withOrigin("origin").build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aUserDetails().withUsername(null))
                .build();

        manager.authenticate(inputAuth);
    }

    @Test
    public void testAmpersatInName() {
        String name = "filip@hanik";
        ExternalLoginAuthenticationManager manager = aManager()
                .withOrigin("origin")
                .withUaaUser(aUaaUser().withId("userId").withUsername(name).withOrigin("origin"))
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aUserDetails().withUsername(name))
                .build();

        Authentication result = manager.authenticate(inputAuth);

        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals(name, uaaAuthentication.getPrincipal().getName());
        assertEquals("origin", uaaAuthentication.getPrincipal().getOrigin());
        assertEquals("userId", uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testAmpersatInEndOfName() {
        String name = "filip@hanik@";
        String expectedTransformedName = "filiphanik@user.from.origin.cf";

        ExternalLoginAuthenticationManager manager = aManager()
                .withOrigin("origin")
                .withInitiallyMissingUaaUser(aUaaUser().withId("userId").withUsername(name).withOrigin("origin"))
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aUserDetails().withUsername(name))
                .build();


        ApplicationEventPublisher applicationEventPublisher = mock(ApplicationEventPublisher.class);
        manager.setApplicationEventPublisher(applicationEventPublisher);

        Authentication result = manager.authenticate(inputAuth);

        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals(name, uaaAuthentication.getPrincipal().getName());
        assertEquals("origin", uaaAuthentication.getPrincipal().getOrigin());
        assertEquals("userId", uaaAuthentication.getPrincipal().getId());

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);

        verify(applicationEventPublisher, times(2)).publishEvent(userArgumentCaptor.capture());

        assertEquals(2, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().get(0);
        assertEquals("origin", event.getUser().getOrigin());
        assertEquals(expectedTransformedName, event.getUser().getEmail());
    }

    @Test(expected = BadCredentialsException.class)
    public void testAuthenticateUserInsertFails() {
        UaaUserDatabase uaaUserDatabase = mock(UaaUserDatabase.class);
        when(uaaUserDatabase.retrieveUserByName(any(), any())).thenThrow(new UsernameNotFoundException(""));

        ExternalLoginAuthenticationManager manager = aManager().withUaaUserDB(uaaUserDatabase).build();
        Authentication inputAuth = anAuthentication().build();

        manager.authenticate(inputAuth);
    }

    @Test
    public void testAuthenticateLdapUserDetailsPrincipal() {
        String username = "user1";
        String dn = "cn=" + username + ",ou=Users,dc=test,dc=com";

        String origin = "ldap";
        String userId = "userId";
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .withOrigin(origin)
                .withUaaUser(aUaaUser().withId(userId).withUsername(username).withOrigin(origin))
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(anLdapUserDetails().withUsername(username).withDn(dn))
                .build();

        Authentication result = manager.authenticate(inputAuth);

        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals(username, uaaAuthentication.getPrincipal().getName());
        assertEquals(origin, uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());
    }

    @Test
    public void testLdapShadowUserCreationDisabled() {
        String username = "user1";
        String dn = "cn=" + username + ",ou=Users,dc=test,dc=com";

        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .addShadowUser(false)
                .withApplicationEventPublisher(publisher)
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(anLdapUserDetails().withUsername(username).withDn(dn))
                .build();

        try {
            manager.authenticate(inputAuth);
            fail("Expected authentication to fail with an exception.");
        } catch (AccountNotPreCreatedException ex) {
            assertThat(ex.getMessage(), containsString("user account must be pre-created"));
        }

        verify(publisher, times(0)).publishEvent(any());
    }

    @Test
    public void testAuthenticateCreateUserWithLdapUserDetailsPrincipal() {
        String username = "user1";
        String dn = "cn=" + username + ",ou=Users,dc=test,dc=com";
        String origin = "ldap";
        String userId = "userId";
        String email = "joe@test.org";

        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .withOrigin(origin)
                .withInitiallyMissingUaaUser(aUaaUser().withId(userId).withUsername(username).withOrigin(origin).withEmail(email))
                .withApplicationEventPublisher(publisher)
                .build();


        Authentication inputAuth = anAuthentication()
                .withPrincipal(
                        anExtendedLdapUserImpl()
                                .withLdapUserDetails(anLdapUserDetails().withUsername(username).withDn(dn).build())
                                .withMailAttribute("email", email)
                                .build())
                .build();

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals(username, uaaAuthentication.getPrincipal().getName());
        assertEquals(origin, uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, event.getUser().getOrigin());
        assertEquals(dn, event.getUser().getExternalId());
    }

    @Test
    public void testAuthenticateCreateUserWithUserDetailsPrincipal() {
        String username = "user1";
        String origin = "ldap";
        String userId = "userId";

        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .withOrigin(origin)
                .withInitiallyMissingUaaUser(aUaaUser().withId(userId).withUsername(username).withOrigin(origin))
                .withApplicationEventPublisher(publisher)
                .build();


        Authentication inputAuth = anAuthentication()
                .withPrincipal(aUserDetails().withUsername(username))
                .build();

        Authentication result = manager.authenticate(inputAuth);
        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals(username, uaaAuthentication.getPrincipal().getName());
        assertEquals(origin, uaaAuthentication.getPrincipal().getOrigin());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, event.getUser().getOrigin());
        //incorrect default_user details - we wont be able to get the correct external ID
        assertEquals(username, event.getUser().getExternalId());
    }

    @Test
    public void testAuthenticateInvitedUserWithoutAcceptance() {
        String username = "guyWhoDoesNotAcceptInvites";
        String origin = LDAP;
        String email = "guy@ldap.org";
        String userId = "userId";

        UaaUserDatabase userDb = mock(UaaUserDatabase.class);

        // Invited users are created with their email as their username.
        UaaUser invitedUser = aUaaUser().withUsername(email).withId(userId).withEmail(email).withOrigin(origin).build();
        when(invitedUser.modifyAttributes(anyString(), anyString(), anyString(), anyString(), anyBoolean())).thenReturn(invitedUser);
        UaaUser updatedUser = aUaaUser().withUsername(username).withId(userId).withEmail(email).withOrigin(origin).build();
        when(invitedUser.modifyUsername(username)).thenReturn(updatedUser);

        when(userDb.retrieveUserByName(eq(username), eq(origin))).thenThrow(new UsernameNotFoundException(""));
        when(userDb.retrieveUserByEmail(eq(email), eq(origin))).thenReturn(invitedUser);

        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .withOrigin(origin)
                .withUaaUserDB(userDb)
                .withUaaUser(invitedUser)
                .withApplicationEventPublisher(publisher)
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(
                        aMailableExtendedLdapUserDetails()
                                .withUsername(username)
                                .withEmailAddress(email))
                .build();


        manager.authenticate(inputAuth);
        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, atLeastOnce()).publishEvent(userArgumentCaptor.capture());

        for (ApplicationEvent event : userArgumentCaptor.getAllValues()) {
            assertNotEquals(event.getClass(), NewUserAuthenticatedEvent.class);
        }
    }

    @Test
    public void storeCustomAttributesFalse_AttributesShouldNotBeStored() {
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .storeCustomAttributes(false)
                .build();

        UaaAuthentication inputAuth = aUaaAuthentication()
                .withPrincipal(aUaaPrincipal().withId("id"))
                .build();


        manager.populateAuthenticationAttributes(inputAuth, mock(Authentication.class), null);
        verify(manager.getUserDatabase(), never()).storeUserInfo(anyString(), any());
    }

    @Test
    public void storeCustomAttributesTrue_AttributesShouldBeStored() {
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .storeCustomAttributes(true)
                .build();

        UaaAuthentication inputAuth = aUaaAuthentication()
                .withPrincipal(aUaaPrincipal().withId("id"))
                .build();


        manager.populateAuthenticationAttributes(inputAuth, mock(Authentication.class), null);
        UserInfo userInfo = new UserInfo()
                .setUserAttributes(inputAuth.getUserAttributes())
                .setRoles(new ArrayList<>(inputAuth.getExternalGroups()));

        verify(manager.getUserDatabase(), times(1)).storeUserInfo(eq("id"), eq(userInfo));
    }

    @Test
    public void nullProvider_AttributesShouldNotBeStored() {
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .withIdProviderProvisioning(null)
                .build();

        UaaAuthentication inputAuth = aUaaAuthentication()
                .withPrincipal(aUaaPrincipal().withId("id"))
                .build();


        manager.populateAuthenticationAttributes(inputAuth, mock(Authentication.class), null);
        verify(manager.getUserDatabase(), never()).storeUserInfo(anyString(), any());
    }

    @Test
    public void emptyAttributes_AttributesShouldNotBeStored() {
        ExternalLoginAuthenticationManager manager = anLdapManager()
                .storeCustomAttributes(true)
                .build();

        UaaAuthentication inputAuth = aUaaAuthentication()
                .withPrincipal(aUaaPrincipal().withId("id"))
                .withUserAttributes(new LinkedMultiValueMap<>())
                .build();

        manager.populateAuthenticationAttributes(inputAuth, mock(Authentication.class), null);
        verify(manager.getUserDatabase(), never()).storeUserInfo(anyString(), any());
    }

    @Test
    public void testAuthenticateUserExists() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        String origin = "origin";
        String username = "my_username";
        ExternalLoginAuthenticationManager manager = aManager()
                .withOrigin(origin)
                .withUaaUser(aUaaUser().withUsername(username).withOrigin(origin))
                .withApplicationEventPublisher(publisher)
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aUserDetails().withUsername(username).withPassword("password"))
                .build();


        manager.authenticate(inputAuth);

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(1)).publishEvent(userArgumentCaptor.capture());
        assertEquals(1, userArgumentCaptor.getAllValues().size());
        IdentityProviderAuthenticationSuccessEvent userevent = (IdentityProviderAuthenticationSuccessEvent) userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, userevent.getUser().getOrigin());
        assertEquals(username, userevent.getUser().getUsername());
    }

    @Test
    public void testAuthenticateUserDoesNotExists() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        String origin = "external";
        String username = "my_username";
        String userId = "userId";
        ExternalLoginAuthenticationManager manager = aManager()
                .withOrigin(origin)
                .withInitiallyMissingUaaUser(aUaaUser().withId(userId).withUsername(username).withOrigin(origin))
                .withApplicationEventPublisher(publisher)
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aUserDetails().withUsername(username).withPassword("password"))
                .build();


        Authentication result = manager.authenticate(inputAuth);

        assertNotNull(result);
        assertEquals(UaaAuthentication.class, result.getClass());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
        assertEquals(username, uaaAuthentication.getPrincipal().getName());
        assertEquals(userId, uaaAuthentication.getPrincipal().getId());

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(2)).publishEvent(userArgumentCaptor.capture());
        assertEquals(2, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().get(0);
        assertEquals(origin, event.getUser().getOrigin());
    }

    @Test
    public void enforceDomainsFalse_loginSuccess() {
        String username = "username";
        String email = "email@domain.com";
        ExternalLoginAuthenticationManager manager = aManager()
                .withUaaUser(aUaaUser().withUsername(username))
                .enforceDomains(false)
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aMailableUserDetails().withUsername(username).withEmailAddress(email))
                .build();

        Authentication authenticate = manager.authenticate(inputAuth);
        assertTrue(authenticate.isAuthenticated());
    }

    @Test(expected = EmailDomainNotAllowedException.class)
    public void enforceDomainsTrueWithUnconfiguredDomain_loginFail() {
        String username = "username";
        String email = "email@domain.com";
        List<String> allowedDomains = asList("test.com", "pivotal.io");

        ExternalLoginAuthenticationManager manager = aManager()
                .withUaaUser(aUaaUser().withUsername(username))
                .enforceDomains(true)
                .withEmailDomain(allowedDomains)
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aMailableUserDetails().withUsername(username).withEmailAddress(email))
                .build();

        manager.authenticate(inputAuth);
    }

    @Test
    public void enforceDomainsTrueWithApprovedDomain_loginSuccess() {
        String username = "username";
        String email = "email@pivotal.io";
        List<String> allowedDomains = asList("test.com", "pivotal.io");

        ExternalLoginAuthenticationManager manager = aManager()
                .withUaaUser(aUaaUser().withUsername(username))
                .enforceDomains(true)
                .withEmailDomain(allowedDomains)
                .build();

        Authentication inputAuth = anAuthentication()
                .withPrincipal(aMailableUserDetails().withUsername(username).withEmailAddress(email))
                .build();

        manager.authenticate(inputAuth);
    }

}