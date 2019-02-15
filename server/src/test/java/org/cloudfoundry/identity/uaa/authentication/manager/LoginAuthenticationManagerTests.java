package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserTestFactory;
import org.junit.*;
import org.junit.rules.ExpectedException;
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

/**
 * @author Dave Syer
 */
public class LoginAuthenticationManagerTests {

    private LoginAuthenticationManager manager = new LoginAuthenticationManager();

    private UaaUserDatabase userDatabase = Mockito.mock(UaaUserDatabase.class);

    private TestApplicationEventPublisher<IdentityProviderAuthenticationSuccessEvent> publisher;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void init() {
        publisher = TestApplicationEventPublisher.forEventClass(IdentityProviderAuthenticationSuccessEvent.class);
        manager.setApplicationEventPublisher(publisher);
        manager.setUserDatabase(userDatabase);
        OAuth2Authentication oauth2Authentication = new OAuth2Authentication(new AuthorizationRequest("client", Arrays.asList("read",
                "write")).createOAuth2Request(), null);
        SecurityContextImpl context = new SecurityContextImpl();
        context.setAuthentication(oauth2Authentication);
        SecurityContextHolder.setContext(context);
    }

    @After
    public void clean() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testNotProcessingWrongType() {
        Authentication authentication = manager.authenticate(new UsernamePasswordAuthenticationToken("foo", "bar"));
        assertNull(authentication);
    }

    @Test
    public void testNotProcessingNotAuthenticated() {
        SecurityContextHolder.clearContext();
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertNull(authentication);
    }

    @Test
    public void testHappyDayNoAutoAdd() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getId(), ((UaaPrincipal) authentication.getPrincipal()).getId());
    }

    @Test
    public void testHappyDayWithAuthorities() {
        UaaUser user = UaaUserTestFactory.getAdminUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo"));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getAuthorities(), authentication.getAuthorities());
    }

    @Test(expected = BadCredentialsException.class)
    public void testUserNotFoundNoAutoAdd() {
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        manager.authenticate(UaaAuthenticationTestFactory.getAuthenticationRequest("foo"));
    }

    @Test
    public void testHappyDayAutoAddButWithExistingUser() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo", true));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getId(), ((UaaPrincipal) authentication.getPrincipal()).getId());
    }

    @Test
    public void testHappyDayAutoAddButWithNewUser() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"))
                .thenReturn(user);
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo", true));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getId(), ((UaaPrincipal) authentication.getPrincipal()).getId());
    }

    @Test(expected = BadCredentialsException.class)
    public void testUnsuccessfulAutoAddButWithNewUser() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        Authentication authentication = manager.authenticate(UaaAuthenticationTestFactory
                .getAuthenticationRequest("foo", true));
        assertEquals(user.getUsername(), ((UaaPrincipal) authentication.getPrincipal()).getName());
        assertEquals(user.getId(), ((UaaPrincipal) authentication.getPrincipal()).getId());
    }

    @Test
    public void testAuthenticateWithStrangeNameAndMissingEmail() {
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
    public void uaaOriginNotAllowedForExternalLogin() {
        expectedException.expect(BadCredentialsException.class);
        expectedException.expectMessage("uaa origin not allowed for external login server");

        String username1 = "a@";
        AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest(username1, true);
        Map<String, String> info = new HashMap<>(req1.getInfo());
        info.put(OriginKeys.ORIGIN, OriginKeys.UAA);
        manager.getUser(req1, info);
    }

    @Test
    public void testSuccessfulAuthenticationPublishesEvent() {
        UaaUser user = UaaUserTestFactory.getUser("FOO", "foo", "fo@test.org", "Foo", "Bar");
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenReturn(user);
        AuthzAuthenticationRequest authenticationRequest = UaaAuthenticationTestFactory.getAuthenticationRequest("foo");
        manager.authenticate(authenticationRequest);

        Assert.assertEquals(1, publisher.getEventCount());
        Assert.assertEquals("foo", publisher.getLatestEvent().getUser().getUsername());
    }

    @Test
    public void testNoOutOfBoundsInCaseOfWrongEmailFormat() {
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
