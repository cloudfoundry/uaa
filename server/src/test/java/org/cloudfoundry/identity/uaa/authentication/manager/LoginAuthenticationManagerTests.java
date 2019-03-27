package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserTestFactory;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

@ExtendWith(PollutionPreventionExtension.class)
class LoginAuthenticationManagerTests {

    private LoginAuthenticationManager manager;
    private UaaUserDatabase userDatabase;
    private TestApplicationEventPublisher<IdentityProviderAuthenticationSuccessEvent> publisher;
    private IdentityZoneManager mockIdentityZoneManager;

    @BeforeEach
    void setUp() {
        publisher = TestApplicationEventPublisher.forEventClass(IdentityProviderAuthenticationSuccessEvent.class);
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        manager = new LoginAuthenticationManager(mockIdentityZoneManager);
        manager.setApplicationEventPublisher(publisher);
        userDatabase = mock(UaaUserDatabase.class);
        manager.setUserDatabase(userDatabase);
        OAuth2Authentication oauth2Authentication = new OAuth2Authentication(new AuthorizationRequest("client", Arrays.asList("read",
                "write")).createOAuth2Request(), null);
        SecurityContextImpl context = new SecurityContextImpl();
        context.setAuthentication(oauth2Authentication);
        SecurityContextHolder.setContext(context);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void emailIsNullNameDoesNotContainCommercialAtReturnsNamePlusDefaultDomain() {
        Map<String, String> attributes = new HashMap<>();
        AuthzAuthenticationRequest request = UaaAuthenticationTestFactory.getAuthenticationRequest("user", true);
        UaaUser user = manager.getUser(request, attributes);
        assertEquals("user@this-default-was-not-configured.invalid", user.getEmail());
    }

    @Test
    void emailIsNullNameContainsLeadingCommericalAtReturnsNamePlusDefaultDomain() {
        Map<String, String> attributes = new HashMap<>();
        AuthzAuthenticationRequest request = UaaAuthenticationTestFactory.getAuthenticationRequest("@user", true);
        UaaUser user = manager.getUser(request, attributes);
        assertEquals("user@this-default-was-not-configured.invalid", user.getEmail());
    }

    @Test
    void emailIsNullNameContainsTrailingCommericalAtReturnsNamePlusDefaultDomain() {
        Map<String, String> attributes = new HashMap<>();
        AuthzAuthenticationRequest request = UaaAuthenticationTestFactory.getAuthenticationRequest("user@", true);
        UaaUser user = manager.getUser(request, attributes);
        assertEquals("user@this-default-was-not-configured.invalid", user.getEmail());
    }

    @Test
    void emailIsNullNameContainsMiddleCommericalAtReturnsNamePlusDefaultDomain() {
        Map<String, String> attributes = new HashMap<>();
        AuthzAuthenticationRequest request = UaaAuthenticationTestFactory.getAuthenticationRequest("user@more-stuff", true);
        UaaUser user = manager.getUser(request, attributes);
        assertEquals("user@more-stuff", user.getEmail());
    }

    @Test
    void testNotProcessingWrongType() {
        Authentication authentication = manager.authenticate(new UsernamePasswordAuthenticationToken("foo", "bar"));
        assertNull(authentication);
    }

    @Test
    void testNotProcessingNotAuthenticated() {
        SecurityContextHolder.clearContext();
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertNull(authentication);
    }

    @Test
    void testHappyDayNoAutoAdd() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getId(), ((UaaPrincipal) authentication.getPrincipal()).getId());
    }

    @Test
    void testHappyDayWithAuthorities() {
        UaaUser user = UaaUserTestFactory.getAdminUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getAuthorities(), authentication.getAuthorities());
    }

    @Test
    void testUserNotFoundNoAutoAdd() {
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        assertThrows(BadCredentialsException.class, () -> manager.authenticate(UaaAuthenticationTestFactory.getAuthenticationRequest("foo")));
    }

    @Test
    void testHappyDayAutoAddButWithExistingUser() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo", true));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getId(), ((UaaPrincipal) authentication.getPrincipal()).getId());
    }

    @Test
    void testHappyDayAutoAddButWithNewUser() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"))
                .thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo", true));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getId(), ((UaaPrincipal) authentication.getPrincipal()).getId());
    }

    @Test
    void testUnsuccessfulAutoAddButWithNewUser() {
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        assertThrows(BadCredentialsException.class, () -> manager.authenticate(UaaAuthenticationTestFactory.getAuthenticationRequest("foo", true)));
    }

    @Test
    void testAuthenticateWithStrangeNameAndMissingEmail() {
        String username1 = "a@";
        AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest(username1, true);
        UaaUser u1 = manager.getUser(req1, req1.getInfo());
        assertEquals(username1, u1.getUsername());

        String username2 = "@a";
        AuthzAuthenticationRequest req2 = UaaAuthenticationTestFactory.getAuthenticationRequest(username2, true);
        UaaUser u2 = manager.getUser(req2, req2.getInfo());
        assertEquals(username2, u2.getUsername());

        String username3 = "a@b@c";
        AuthzAuthenticationRequest req3 = UaaAuthenticationTestFactory.getAuthenticationRequest(username3, true);
        UaaUser u3 = manager.getUser(req3, req3.getInfo());
        assertEquals(username3, u3.getUsername());
    }

    @Test
    void uaaOriginNotAllowedForExternalLogin() {
        String username1 = "a@";
        AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest(username1, true);
        Map<String, String> info = new HashMap<>(req1.getInfo());
        info.put(OriginKeys.ORIGIN, OriginKeys.UAA);
        assertThrows(BadCredentialsException.class, () -> manager.getUser(req1, info), "uaa origin not allowed for external login server");
    }

    @Test
    void testSuccessfulAuthenticationPublishesEvent() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        AuthzAuthenticationRequest authenticationRequest = UaaAuthenticationTestFactory.getAuthenticationRequest("foo");
        manager.authenticate(authenticationRequest);

        assertEquals(1, publisher.getEventCount());
        assertEquals("foo", publisher.getLatestEvent().getUser().getUsername());
    }

    @Test
    void testNoOutOfBoundsInCaseOfWrongEmailFormat() {
        // use an email without the '@' sign and provide no name and familyname to trigger the potential bug
        String username = "newuser";
        String email = "noAtSign";
        AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest(username, true);
        Map<String, String> info = new HashMap<>(req1.getInfo());
        info.put("email", email);
        UaaUser u1 = manager.getUser(req1, info);
        assertNotNull(u1);
        assertEquals(username, u1.getUsername());
        assertNotNull(u1.getFamilyName());
        assertNotNull(u1.getGivenName());
    }

}
