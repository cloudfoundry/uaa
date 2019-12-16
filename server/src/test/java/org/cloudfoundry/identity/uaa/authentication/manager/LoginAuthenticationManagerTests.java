package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserTestFactory;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
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
import java.util.Collections;
import java.util.HashMap;

import static org.cloudfoundry.identity.uaa.user.UaaUserMatcher.aUaaUser;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.is;
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
    void testUnsuccessfulAutoAddButWithNewUser() {
        Mockito.when(userDatabase.retrieveUserByName("foo", OriginKeys.LOGIN_SERVER)).thenThrow(new UsernameNotFoundException("planned"));
        assertThrows(BadCredentialsException.class, () -> manager.authenticate(UaaAuthenticationTestFactory.getAuthenticationRequest("foo", true)));
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


    @Nested
    class GetUser {
        @Test
        void uaaOriginNotAllowedForExternalLogin() {
            AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest("user", true);
            assertThrowsWithMessageThat(
                    BadCredentialsException.class,
                    () -> manager.getUser(req1, Collections.singletonMap(OriginKeys.ORIGIN, OriginKeys.UAA)),
                    is("uaa origin not allowed for external login server")
            );
        }

        @Test
        void byDefault() {
            AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest("user", true);
            HashMap<String, String> info = new HashMap<>();
            info.put("email", "user@example.com");
            info.put("given_name", "Jane");
            info.put("family_name", "Doe");
            info.put(OriginKeys.ORIGIN, "test-origin");
            UaaUser user = manager.getUser(req1, info);

            assertThat(user, is(
                aUaaUser()
                    .withUsername("user")
                    .withEmail("user@example.com")
                    .withGivenName("Jane")
                    .withFamilyName("Doe")
                    .withPassword("")
                    .withAuthorities(Matchers.equalTo(UaaAuthority.USER_AUTHORITIES))
                    .withOrigin("test-origin")
                    .withExternalId("user")
                    .withZoneId(mockIdentityZoneManager.getCurrentIdentityZoneId())
            ));
        }

        @Test
        void withoutOrigin() {
            AuthzAuthenticationRequest req1 = UaaAuthenticationTestFactory.getAuthenticationRequest("user", true);
            HashMap<String, String> info = new HashMap<>();
            info.put("email", "user@example.com");
            UaaUser user = manager.getUser(req1, info);

            assertThat(user, is(
                    aUaaUser()
                            .withUsername("user")
                            .withEmail("user@example.com")
                            .withPassword("")
                            .withAuthorities(Matchers.equalTo(UaaAuthority.USER_AUTHORITIES))
                            .withOrigin(OriginKeys.LOGIN_SERVER)
                            .withExternalId("user")
                            .withZoneId(mockIdentityZoneManager.getCurrentIdentityZoneId())
            ));
        }
    }
}
